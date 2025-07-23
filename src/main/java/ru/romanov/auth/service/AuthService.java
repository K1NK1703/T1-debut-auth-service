package ru.romanov.auth.service;

import ru.romanov.auth.dto.request.LoginRequestDTO;
import ru.romanov.auth.dto.request.RefreshTokenRequestDTO;
import ru.romanov.auth.dto.request.RegisterRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.AuthResponseDTO;

public interface AuthService {

    ApiResponseDTO registerUser(RegisterRequestDTO registerRequest);

    AuthResponseDTO authenticateUser(LoginRequestDTO loginRequest);

    AuthResponseDTO refreshToken(RefreshTokenRequestDTO request);

    ApiResponseDTO logout(String refreshToken);

    ApiResponseDTO revokeToken(String refreshToken);
}
