package ru.romanov.auth.dto.response;

public record ApiResponseDTO(
        boolean success,
        String message,
        Object data
) {
    public ApiResponseDTO(boolean success, String message) {
        this(success, message, null);
    }
}
