package ru.romanov.auth.dto.request;

import jakarta.validation.constraints.NotEmpty;
import ru.romanov.auth.model.Role;

import java.util.Set;

public record UpdateUserRolesRequestDTO(
        @NotEmpty(message = "Роли не могут быть пустыми") Set<Role> roles
) {}
