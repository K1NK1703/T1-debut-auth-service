package ru.romanov.auth.service;

import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.model.Role;
import ru.romanov.auth.model.entity.User;

import java.util.List;
import java.util.Set;

public interface UserService {

    List<User> getAllUsers();

    ApiResponseDTO updateUserRoles(Long userId, Set<Role> roles);

    ApiResponseDTO deleteUser(Long userId);

    User createUser(String login, String encodedPassword, String email);

    User findByLogin(String login);

    User findById(Long id);

    ApiResponseDTO changePassword(String login, String currentPassword, String newPassword);

    ApiResponseDTO updateProfile(String login, String newLogin, String newEmail);

    boolean existsByLogin(String login);

    boolean existsByEmail(String email);
}
