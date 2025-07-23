package ru.romanov.auth.dto.response;

import java.time.LocalDateTime;

public record TokenValidationResponseDTO(
        boolean valid,
        String login,
        LocalDateTime expiresAt,
        String message
) {
    public static TokenValidationResponseDTO valid(String login, LocalDateTime expiresAt) {
        return new TokenValidationResponseDTO(true, login, expiresAt, "Токен действителен");
    }

    public static TokenValidationResponseDTO invalid(String message) {
        return new TokenValidationResponseDTO(false, null, null, message);
    }
}
