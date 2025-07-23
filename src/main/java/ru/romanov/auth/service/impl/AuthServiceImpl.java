package ru.romanov.auth.service.impl;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.romanov.auth.dto.request.LoginRequestDTO;
import ru.romanov.auth.dto.request.RefreshTokenRequestDTO;
import ru.romanov.auth.dto.request.RegisterRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.AuthResponseDTO;
import ru.romanov.auth.exception.AuthException;
import ru.romanov.auth.model.entity.RefreshToken;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.security.JwtUtilService;
import ru.romanov.auth.service.AuthService;
import ru.romanov.auth.service.TokenService;
import ru.romanov.auth.service.UserService;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthServiceImpl implements AuthService {

    UserService userService;
    TokenService tokenService;
    JwtUtilService jwtUtilService;
    PasswordEncoder passwordEncoder;
    AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public ApiResponseDTO registerUser(RegisterRequestDTO registerRequestDTO) {
        if (userService.existsByLogin(registerRequestDTO.login())) {
            return new ApiResponseDTO(false, "Пользователь с таким логином уже существует!");
        }

        if (userService.existsByEmail(registerRequestDTO.email())) {
            return new ApiResponseDTO(false, "Пользователь с таким email уже существует!");
        }

        User savedUser = userService.createUser(
                registerRequestDTO.login(),
                passwordEncoder.encode(registerRequestDTO.password()),
                registerRequestDTO.email()
        );

        return new ApiResponseDTO(true, "Пользователь успешно зарегистрирован",
                new AuthResponseDTO.UserInfo(savedUser.getId(), savedUser.getLogin(),
                        savedUser.getEmail(), savedUser.getRoles()));
    }

    @Override
    @Transactional
    public AuthResponseDTO authenticateUser(LoginRequestDTO loginRequestDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDTO.login(),
                            loginRequestDTO.password())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            User user = userService.findByLogin(loginRequestDTO.login());

            String accessToken = jwtUtilService.generateAccessToken(user.getLogin(), user.getRoles());
            RefreshToken refreshToken = tokenService.createRefreshToken(user);

            LocalDateTime expiresAt = LocalDateTime.now()
                    .plusSeconds(jwtUtilService.getJwtExpirationInSeconds());

            AuthResponseDTO.UserInfo userInfo = new AuthResponseDTO.UserInfo(
                    user.getId(), user.getLogin(), user.getEmail(), user.getRoles());

            return new AuthResponseDTO(accessToken, refreshToken.getToken(), expiresAt, userInfo);
        } catch (BadCredentialsException e) {
            throw new AuthException("Неверный логин или пароль");
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO refreshToken(RefreshTokenRequestDTO requestDTO) {
        String requestRefreshToken = requestDTO.refreshToken();

        RefreshToken refreshToken = tokenService.findByToken(requestRefreshToken)
                .map(tokenService::verifyExpiration)
                .orElseThrow(() -> new AuthException("Refresh token не найден или истек"));

        User user = refreshToken.getUser();
        String newAccessToken = jwtUtilService.generateAccessToken(user.getLogin(), user.getRoles());

        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(jwtUtilService.getJwtExpirationInSeconds());

        AuthResponseDTO.UserInfo userInfo = new AuthResponseDTO.UserInfo(
                user.getId(), user.getLogin(), user.getEmail(), user.getRoles());

        return new AuthResponseDTO(newAccessToken, requestRefreshToken, expiresAt, userInfo);
    }

    @Override
    @Transactional
    public ApiResponseDTO logout(String refreshToken) {
        if (refreshToken != null) {
            tokenService.revokeToken(refreshToken);
        }
        return new ApiResponseDTO(true, "Успешный выход из системы");
    }

    @Override
    @Transactional
    public ApiResponseDTO revokeToken(String refreshToken) {
        tokenService.revokeToken(refreshToken);
        return new ApiResponseDTO(true, "Токен успешно отозван");
    }
}
