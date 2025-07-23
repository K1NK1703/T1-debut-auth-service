package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateProfileRequestDTO(
        @NotBlank(message = "Логин не может быть пустым")
        @Size(min = 4, max = 50, message = "Логин должен содержать от 4 до 50 символов")
        String login,

        @Email(message = "Некорректный формат email")
        @NotBlank(message = "Email не может быть пустым")
        String email
) {}
