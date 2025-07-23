package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequestDTO(
        @NotBlank(message = "Логин не может быть пустым")
        @Size(min = 4, max = 50, message = "Логин должен содержать от 4 до 50 символов")
        String login,

        @NotBlank(message = "Пароль не может быть пустым")
        @Size(min = 8, max = 100, message = "Пароль должен содержать минимум 8 символов")
        String password,

        @Email(message = "Некорректный формат эл. почты")
        @NotBlank(message = "Email не может быть пустым")
        String email
) {}
