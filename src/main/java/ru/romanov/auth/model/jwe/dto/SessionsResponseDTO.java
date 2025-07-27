package ru.romanov.auth.model.jwe.dto;

import lombok.Data;
import lombok.Builder;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import ru.romanov.auth.model.jwe.SessionInfo;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SessionsResponseDTO {
    boolean success = true;
    String message;
    List<SessionInfo> sessions;
    int totalSessions;
}
