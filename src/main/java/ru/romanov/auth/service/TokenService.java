package ru.romanov.auth.service;

import ru.romanov.auth.model.entity.RefreshToken;
import ru.romanov.auth.model.entity.User;

import java.util.List;
import java.util.Optional;

public interface TokenService {

    RefreshToken createRefreshToken(User user);

    Optional<RefreshToken> findByToken(String token);

    RefreshToken verifyExpiration(RefreshToken token);

    void revokeToken(String token);

    void revokeAllUserTokens(User user);

    List<RefreshToken> getAllActiveTokens();

    void cleanupExpiredTokens();
}
