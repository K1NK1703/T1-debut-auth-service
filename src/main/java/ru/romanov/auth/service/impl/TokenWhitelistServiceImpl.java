package ru.romanov.auth.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import ru.romanov.auth.model.jwe.ActiveSession;
import ru.romanov.auth.service.TokenWhitelistService;

import java.util.Map;
import java.util.Date;
import java.util.List;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
@ConditionalOnProperty(name = "jwe.enabled", havingValue = "true", matchIfMissing = true)
public class TokenWhitelistServiceImpl implements TokenWhitelistService {

    private final Map<String, ActiveSession> activeSessions = new ConcurrentHashMap<>();

    public void registerActiveSession(String jwtId, String login, String sessionId, Date expiresAt) {
        ActiveSession session = ActiveSession.builder()
                .jwtId(jwtId)
                .login(login)
                .sessionId(sessionId)
                .createdAt(new Date())
                .expiresAt(expiresAt)
                .lastAccessTime(new Date())
                .active(true)
                .build();

        activeSessions.put(jwtId, session);
        log.info("Зарегистрирована активная сессия: user={}, jwtId={}, sessionId={}",
                login, jwtId, sessionId);
    }

    public boolean isTokenActive(String jwtId) {
        ActiveSession session = activeSessions.get(jwtId);

        if (session == null) {
            log.debug("Токен не найден в белом списке: {}", jwtId);
            return false;
        }

        if (session.getExpiresAt().before(new Date())) {
            log.debug("Срок действия токена истек, он удален из белого списка: {}", jwtId);
            activeSessions.remove(jwtId);
            return false;
        }

        if (!session.isActive()) {
            log.debug("Сессия неактивна: {}", jwtId);
            return false;
        }

        session.setLastAccessTime(new Date());

        return true;
    }

    public void deactivateToken(String jwtId) {
        ActiveSession session = activeSessions.get(jwtId);
        if (session != null) {
            session.setActive(false);
            session.setDeactivatedAt(new Date());
            log.info("Токен деактивирован: user={}, jwtId={}", session.getLogin(), jwtId);
        }
    }

    public void deactivateAllUserTokens(String login) {
        int deactivatedCount = 0;

        for (ActiveSession session : activeSessions.values()) {
            if (session.getLogin().equals(login) && session.isActive()) {
                session.setActive(false);
                session.setDeactivatedAt(new Date());
                deactivatedCount++;
            }
        }

        log.info("Деактивированные токены {} для пользователя: {}", deactivatedCount, login);
    }

    public List<ActiveSession> getUserActiveSessions(String login) {
        return activeSessions.values().stream()
                .filter(session -> session.getLogin().equals(login))
                .filter(session -> isTokenActive(session.getJwtId()))
                .collect(Collectors.toList());
    }

    @Scheduled(fixedDelay = 300000)
    public void cleanupExpiredSessions() {
        int removedCount = 0;
        Date now = new Date();

        Iterator<Map.Entry<String, ActiveSession>> iterator = activeSessions.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ActiveSession> entry = iterator.next();
            ActiveSession session = entry.getValue();

            if (session.getExpiresAt().before(now)) {
                iterator.remove();
                removedCount++;
            } else if (!session.isActive() && session.getDeactivatedAt() != null) {
                long hoursSinceDeactivation = (now.getTime() - session.getDeactivatedAt().getTime()) / (1000 * 60 * 60);
                if (hoursSinceDeactivation > 1) {
                    iterator.remove();
                    removedCount++;
                }
            }
        }

        if (removedCount > 0) {
            log.info("Очищены {} просроченные/неактивные сессии", removedCount);
        }
    }
}
