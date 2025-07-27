package ru.romanov.auth.rest.out.jwe;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import ru.romanov.auth.dto.request.LoginRequestDTO;
import ru.romanov.auth.dto.request.RefreshTokenRequestDTO;
import ru.romanov.auth.dto.request.RegisterRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.AuthResponseDTO;
import ru.romanov.auth.exception.AuthException;
import ru.romanov.auth.model.jwe.ActiveSession;
import ru.romanov.auth.model.jwe.SecureTokenData;
import ru.romanov.auth.model.jwe.SessionInfo;
import ru.romanov.auth.model.jwe.dto.SessionsResponseDTO;
import ru.romanov.auth.security.jwe.EnhancedJwtUtilService;
import ru.romanov.auth.service.AuthService;
import ru.romanov.auth.service.TokenWhitelistService;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Validated
@ConditionalOnProperty(name = "jwe.enabled", havingValue = "true", matchIfMissing = true)
public class AuthJweRestController {

    AuthService authService;
    EnhancedJwtUtilService jwtUtilService;
    TokenWhitelistService tokenWhitelistService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequest) {
        try {
            AuthResponseDTO response = authService.authenticateUser(loginRequest);

            return ResponseEntity.ok(response);

        } catch (AuthException e) {
            log.warn("Не удалось выполнить аутентификацию пользователя: {}", loginRequest.login());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage());
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO> registerUser(@Valid @RequestBody RegisterRequestDTO registerRequest) {
        try {
            ApiResponseDTO response = authService.registerUser(registerRequest);

            if (response.success()) {
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            } else {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
            }

        } catch (Exception e) {
            log.error("Ошибка регистрации", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDTO(false, "Ошибка регистрации"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(
            @Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequest) {

        try {
            AuthResponseDTO response = authService.refreshToken(refreshTokenRequest);
            return ResponseEntity.ok(response);

        } catch (AuthException e) {
            log.warn("Ошибка обновления токена: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO> logout(HttpServletRequest request) {
        try {
            String token = extractTokenFromRequest(request);

            if (StringUtils.hasText(token)) {
                try {
                    SecureTokenData tokenData = jwtUtilService.validateAndDecryptToken(token);

                    tokenWhitelistService.deactivateToken(tokenData.getJwtId());

                    log.info("Пользователь вышел из системы: {}", tokenData.getLogin());
                } catch (Exception e) {
                    log.debug("Не удалось извлечь информацию о пользователе из токена во время выхода из системы");
                }

                SecurityContextHolder.clearContext();
            }

            return ResponseEntity.ok(new ApiResponseDTO(true, "Успешный выход из системы"));

        } catch (Exception e) {
            log.error("Ошибка выхода из системы", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDTO(false, "Ошибка выхода из системы"));
        }
    }

    @PostMapping("/revoke")
    public ResponseEntity<ApiResponseDTO> revokeToken(@Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequest) {
        try {
            ApiResponseDTO response = authService.revokeToken(refreshTokenRequest.refreshToken());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Token revocation failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDTO(false, "Token revocation failed"));
        }
    }

    @PostMapping("/revoke-all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseDTO> revokeAllTokens(@RequestParam String login) {
        try {
            tokenWhitelistService.deactivateAllUserTokens(login);

            log.info("Все токены отозваны у пользователя: {}", login);

            return ResponseEntity.ok(new ApiResponseDTO(
                    true,
                    String.format("Все токены отозваны у пользователя: %s", login))
            );

        } catch (Exception e) {
            log.error("Не удалось отозвать токен у пользователя: {}", login, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDTO(false, "Не удалось отозвать токены"));
        }
    }

    @GetMapping("/sessions")
    public ResponseEntity<SessionsResponseDTO> getUserSessions(Authentication authentication) {
        try {
            String login = authentication.getName();
            List<ActiveSession> activeSessions = tokenWhitelistService.getUserActiveSessions(login);

            List<SessionInfo> sessionInfos = activeSessions.stream()
                    .map(session -> SessionInfo.builder()
                            .sessionId(session.getSessionId())
                            .createdAt(session.getCreatedAt())
                            .lastAccessTime(session.getLastAccessTime())
                            .build())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(SessionsResponseDTO.builder()
                    .success(true)
                    .sessions(sessionInfos)
                    .totalSessions(sessionInfos.size())
                    .build());

        } catch (Exception e) {
            log.error("Не удалось получить доступ к сессиям пользователя", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SessionsResponseDTO.builder()
                            .success(false)
                            .message("Не удалось восстановить сессии")
                            .build());
        }
    }


    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
