package ru.romanov.auth.rest.out;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.TokenValidationResponseDTO;
import ru.romanov.auth.security.JwtUtilService;
import ru.romanov.auth.service.TokenService;
import ru.romanov.auth.util.UserSecurity;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/token")
@CrossOrigin(origins = "*", maxAge = 3600)
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class TokenRestController {

    TokenService tokenService;
    JwtUtilService jwtUtilService;

    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponseDTO> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");

            if (jwtUtilService.validateToken(token)) {
                String login = jwtUtilService.getLoginFromToken(token);
                var expiresAt = jwtUtilService.getExpirationFromToken(token);

                return ResponseEntity.ok(TokenValidationResponseDTO.valid(login, expiresAt));
            } else {
                return ResponseEntity.ok(TokenValidationResponseDTO.invalid("Токен недействителен"));
            }
        } catch (Exception e) {
            return ResponseEntity.ok(TokenValidationResponseDTO.invalid("Ошибка валидации токена"));
        }
    }

    @GetMapping("/info")
    public ResponseEntity<Object> getTokenInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserSecurity userDetails = (UserSecurity) authentication.getPrincipal();

        Map<String, Object> tokenInfo = new HashMap<>();
        tokenInfo.put("login", userDetails.getUsername());
        tokenInfo.put("email", userDetails.getEmail());
        tokenInfo.put("authorities", userDetails.getAuthorities());
        tokenInfo.put("authenticated", authentication.isAuthenticated());

        return ResponseEntity.ok(new ApiResponseDTO(true, "Информация о токене", tokenInfo));
    }

    @DeleteMapping("/revoke-all")
    public ResponseEntity<ApiResponseDTO> revokeAllMyTokens() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserSecurity userSecurity = (UserSecurity) authentication.getPrincipal();

        tokenService.revokeAllUserTokens(userSecurity.user());

        return ResponseEntity.ok(new ApiResponseDTO(true, "Все ваши токены отозваны"));
    }
}
