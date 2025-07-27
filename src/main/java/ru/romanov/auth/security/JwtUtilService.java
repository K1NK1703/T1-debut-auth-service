package ru.romanov.auth.security;

import ru.romanov.auth.model.entity.User;

import java.time.LocalDateTime;

public interface JwtUtilService {

    String generateAccessToken(User user);

    boolean validateToken(String token);

    String getLoginFromToken(String token);

    LocalDateTime getExpirationFromToken(String token);
}
