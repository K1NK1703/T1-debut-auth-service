package ru.romanov.auth.service.impl;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.exception.UserNotFoundException;
import ru.romanov.auth.model.Role;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.repository.UserRepository;
import ru.romanov.auth.service.TokenService;
import ru.romanov.auth.service.UserService;

import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserServiceImpl implements UserService {

    UserRepository userRepository;
    TokenService tokenService;
    PasswordEncoder passwordEncoder;

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ApiResponseDTO updateUserRoles(Long userId, Set<Role> roles) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));

        user.setRoles(roles);
        userRepository.save(user);

        tokenService.revokeAllUserTokens(user);

        return new ApiResponseDTO(true, "Роли пользователя успешно обновлены");
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ApiResponseDTO deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));

        tokenService.revokeAllUserTokens(user);

        userRepository.delete(user);
        return new ApiResponseDTO(true, "Пользователь успешно удалён");
    }

    @Override
    @Transactional
    public User createUser(String login, String encodedPassword, String email) {
        User user = new User(login, encodedPassword, email);
        user.getRoles().add(Role.GUEST);
        return userRepository.save(user);
    }

    @Override
    public User findByLogin(String login) {
        return userRepository.findByLogin(login)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));
    }

    @Override
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));
    }

    @Override
    @Transactional
    public ApiResponseDTO changePassword(String login, String currentPassword, String newPassword) {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            return new ApiResponseDTO(false, "Неверный текущий пароль");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        tokenService.revokeAllUserTokens(user);

        return new ApiResponseDTO(true, "Пароль успешно изменён");
    }

    @Override
    @Transactional
    public ApiResponseDTO updateProfile(String login, String newLogin, String newEmail) {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден"));

        if (!login.equals(newLogin) && userRepository.existsByLogin(newLogin)) {
            return new ApiResponseDTO(false, "Пользователь с таким логином уже существует");
        }

        if (!user.getEmail().equals(newEmail) && userRepository.existsByEmail(newEmail)) {
            return new ApiResponseDTO(false, "Пользователь с таким email уже существует");
        }

        user.setLogin(newLogin);
        user.setEmail(newEmail);
        userRepository.save(user);

        return new ApiResponseDTO(true, "Профиль успешно обновлён");
    }

    @Override
    public boolean existsByLogin(String login) {
        return userRepository.existsByLogin(login);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}
