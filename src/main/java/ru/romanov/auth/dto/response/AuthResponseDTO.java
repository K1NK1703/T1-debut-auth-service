package ru.romanov.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import ru.romanov.auth.model.Role;

import java.time.LocalDateTime;
import java.util.Set;

public record AuthResponseDTO(
        String accessToken,
        String refreshToken,
        @JsonProperty("tokenType") String tokenType,
        LocalDateTime expiresAt,
        UserInfo user
) {
    public AuthResponseDTO(String accessToken, String refreshToken, LocalDateTime expiresAt, UserInfo user) {
        this(accessToken, refreshToken, "Bearer", expiresAt, user);
    }

    public record UserInfo(
            Long id,
            String login,
            String email,
            Set<Role> roles
    ) {}
}
