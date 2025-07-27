package ru.romanov.auth.model.jwe;

import lombok.Data;
import lombok.Builder;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
    public class SensitivePayload {
    Long userId;
    String email;
    Set<String> roles;
    String sessionId;
    String fingerprint;
}
