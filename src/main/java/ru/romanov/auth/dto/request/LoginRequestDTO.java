package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequestDTO(
        @NotBlank(message = "Логин не может быть пустым")
        @Size(min = 4, max = 50, message = "Длина логина должна составлять от 4 до 50 символов")
        String login,

        @NotBlank(message = "Пароль не может быть пустым")
        @Size(min = 8, message = "Пароль должен содержать не менее 8 символов")
        String password
) {}
