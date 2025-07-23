package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequestDTO(
        @NotBlank(message = "Текущий пароль не может быть пустым")
        String currentPassword,

        @NotBlank(message = "Новый пароль не может быть пустым")
        @Size(min = 8, max = 100, message = "Новый пароль должен содержать минимум 8 символов")
        String newPassword
) {}
