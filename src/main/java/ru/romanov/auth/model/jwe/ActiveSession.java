package ru.romanov.auth.model.jwe;

import lombok.Data;
import lombok.Builder;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ActiveSession {
    String jwtId;
    String login;
    String sessionId;
    Date createdAt;
    Date expiresAt;
    Date lastAccessTime;
    Date deactivatedAt;
    boolean active;

    String ipAddress;
    String userAgent;
}
