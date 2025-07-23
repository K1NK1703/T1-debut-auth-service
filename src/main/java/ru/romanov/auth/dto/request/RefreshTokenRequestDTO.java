package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequestDTO(
        @NotBlank(message = "Refresh token не может быть пустым") String refreshToken
) {}
