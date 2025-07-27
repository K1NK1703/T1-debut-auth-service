package ru.romanov.auth.model.jwe;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.FieldDefaults;

import java.util.Date;
import java.util.Set;

@Data
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SecureTokenData {
    String login;
    Long userId;
    String email;
    Set<String> roles;
    String sessionId;
    String jwtId;
    Date issuedAt;
    Date expiresAt;
}
