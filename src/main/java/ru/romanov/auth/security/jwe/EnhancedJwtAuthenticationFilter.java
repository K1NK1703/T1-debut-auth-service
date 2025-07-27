package ru.romanov.auth.security.jwe;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.romanov.auth.exception.TokenValidationException;
import ru.romanov.auth.model.Role;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.model.jwe.SecureTokenData;
import ru.romanov.auth.security.AuthenticationFilter;
import ru.romanov.auth.service.TokenWhitelistService;
import ru.romanov.auth.util.UserSecurity;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Primary
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@ConditionalOnProperty(name = "jwe.enabled", havingValue = "true", matchIfMissing = true)
public class EnhancedJwtAuthenticationFilter extends OncePerRequestFilter implements AuthenticationFilter {

    EnhancedJwtUtilService jwtUtilService;
    TokenWhitelistService tokenWhitelistService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String jweToken = getJwtFromRequest(request);

            if (StringUtils.hasText(jweToken)) {
                authenticateWithSecureToken(jweToken);
            }

        } catch (TokenValidationException e) {
            log.warn("Не удалось выполнить проверку токена: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            setErrorResponse(request, response, "INVALID_TOKEN", "Token validation failed");
            return;
        } catch (Exception e) {
            log.error("Ошибка аутентификации", e);
            SecurityContextHolder.clearContext();
            setErrorResponse(request, response, "AUTHENTICATION_ERROR", "Authentication failed");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateWithSecureToken(String jweToken) {
        SecureTokenData tokenData = jwtUtilService.validateAndDecryptToken(jweToken);

        if (!tokenWhitelistService.isTokenActive(tokenData.getJwtId())) {
            throw new TokenValidationException("Токен, не включённый в активные сессии (белый список)");
        }

        UserDetails userDetails = createUserDetailsFromToken(tokenData);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("Успешно прошедший проверку подлинности пользователь: {}", tokenData.getLogin());
    }

    private UserDetails createUserDetailsFromToken(SecureTokenData tokenData) {
        Set<GrantedAuthority> authorities = tokenData.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(String.format("ROLE_%s", role)))
                .collect(Collectors.toSet());

        User user = User.builder()
                .id(tokenData.getUserId())
                .login(tokenData.getLogin())
                .email(tokenData.getEmail())
                .roles(tokenData.getRoles().stream()
                        .map(Role::valueOf)
                        .collect(Collectors.toSet()))
                .build();

        return new UserSecurity(user);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private void setErrorResponse(HttpServletRequest request,
                                  HttpServletResponse response,
                                  String errorCode,
                                  String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        error.put("error", errorCode);
        error.put("message", message);
        error.put("path", request.getRequestURI());

        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(error));
    }
}
