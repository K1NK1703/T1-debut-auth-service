package ru.romanov.auth.service;

import ru.romanov.auth.model.jwe.ActiveSession;

import java.util.Date;
import java.util.List;

public interface TokenWhitelistService {

    void registerActiveSession(String jwtId, String login, String sessionId, Date expiresAt);

    boolean isTokenActive(String jwtId);

    void deactivateToken(String jwtId);

    void deactivateAllUserTokens(String login);

    List<ActiveSession> getUserActiveSessions(String login);

    void cleanupExpiredSessions();
}
