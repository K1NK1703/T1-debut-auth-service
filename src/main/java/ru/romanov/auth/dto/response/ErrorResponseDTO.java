package ru.romanov.auth.dto.response;

import java.time.LocalDateTime;
import java.util.Map;

public record ErrorResponseDTO(
        boolean success,
        String message,
        String error,
        int status,
        LocalDateTime timestamp,
        String path,
        Map<String, String> validationErrors
) {
    public ErrorResponseDTO(String message, String error, int status, String path) {
        this(false, message, error, status, LocalDateTime.now(), path, null);
    }

    public ErrorResponseDTO(String message, String error, int status, String path, Map<String, String> validationErrors) {
        this(false, message, error, status, LocalDateTime.now(), path, validationErrors);
    }
}
