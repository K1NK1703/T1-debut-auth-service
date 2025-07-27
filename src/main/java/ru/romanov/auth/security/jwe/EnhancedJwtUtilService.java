package ru.romanov.auth.security.jwe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import ru.romanov.auth.exception.TokenGenerationException;
import ru.romanov.auth.exception.TokenValidationException;
import ru.romanov.auth.model.Role;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.model.jwe.SecureTokenData;
import ru.romanov.auth.model.jwe.SensitivePayload;
import ru.romanov.auth.security.JwtUtilService;
import ru.romanov.auth.service.TokenWhitelistService;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@Primary
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@ConditionalOnProperty(name = "jwe.enabled", havingValue = "true", matchIfMissing = true)
public class EnhancedJwtUtilService implements JwtUtilService {

    @Value("${jwt.secret.key}")
    String secret;

    @Value("${jwt.expiration}")
    int expiration;

    @Value("${jwe.encryption.secret}")
    String encryptionSecret;

    SecretKey encryptionKey;

    final TokenWhitelistService tokenWhitelistService;

    @PostConstruct
    public void init() {
        try {
            if (encryptionSecret.length() < 32) {
                throw new IllegalArgumentException(
                        "Длина секретного кода шифрования должна составлять не менее 32 символов"
                );
            }

            byte[] keyBytes = encryptionSecret.substring(0, 32).getBytes(StandardCharsets.UTF_8);
            this.encryptionKey = new SecretKeySpec(keyBytes, "AES");

            log.info("Ключи шифрования и подписи JWT успешно инициализированы");

        } catch (Exception e) {
            log.error("Ошибка инициализации JWE ключей", e);
            throw new RuntimeException("Ошибка инициализации JWE ключей", e);
        }
    }

    @Override
    public String generateAccessToken(User user) {
        try {
            String jwtId = UUID.randomUUID().toString();
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + expiration * 1000L);

            SecretKey signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

            String baseJwt = Jwts.builder()
                    .id(jwtId)
                    .subject(user.getLogin())
                    .issuedAt(now)
                    .expiration(expiryDate)
                    .signWith(signingKey)
                    .compact();

            String sessionId = generateSessionId();
            SensitivePayload payload = SensitivePayload.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .roles(user.getRoles().stream()
                            .map(Role::name)
                            .collect(Collectors.toSet()))
                    .sessionId(sessionId)
                    .fingerprint(generateFingerprint(user))
                    .build();

            String encryptedPayload = encryptSensitiveData(payload);

            String jweToken = createJWE(baseJwt, encryptedPayload, jwtId);

            tokenWhitelistService.registerActiveSession(jwtId, user.getLogin(), sessionId, expiryDate);

            return jweToken;

        } catch (Exception e) {
            log.error("Ошибка при генерации безопасного токена для пользователя: {}", user.getLogin(), e);
            throw new TokenGenerationException("Не удалось сгенерировать безопасный токен", e);
        }
    }

    public SecureTokenData validateAndDecryptToken(String jweToken) {
        try {
            JWEObject jweObject = JWEObject.parse(jweToken);
            jweObject.decrypt(new DirectDecrypter(encryptionKey.getEncoded()));

            String payloadString = jweObject.getPayload().toString();
            JSONObject payload = (JSONObject) JSONValue.parse(payloadString);
            String baseJwt = payload.getAsString("jwt");
            String encryptedPayload = payload.getAsString("encrypted_data");

            SecretKey signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(baseJwt)
                    .getPayload();

            SensitivePayload sensitiveData = decryptSensitiveData(encryptedPayload);

            validateSecurityConstraints(claims, sensitiveData);

            return SecureTokenData.builder()
                    .login(claims.getSubject())
                    .userId(sensitiveData.getUserId())
                    .email(sensitiveData.getEmail())
                    .roles(sensitiveData.getRoles())
                    .sessionId(sensitiveData.getSessionId())
                    .jwtId(claims.getId())
                    .issuedAt(claims.getIssuedAt())
                    .expiresAt(claims.getExpiration())
                    .build();

        } catch (Exception e) {
            log.error("Не удалось выполнить проверку токена", e);
            throw new TokenValidationException("Недействительный или просроченный токен", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            validateAndDecryptToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getLoginFromToken(String token) {
        try {
            SecureTokenData tokenData = validateAndDecryptToken(token);
            return tokenData.getLogin();
        } catch (Exception e) {
            throw new TokenValidationException("Не удалось извлечь логин из токена", e);
        }
    }

    public LocalDateTime getExpirationFromToken(String token) {
        try {
            SecureTokenData tokenData = validateAndDecryptToken(token);
            return tokenData.getExpiresAt().toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
        } catch (Exception e) {
            throw new TokenValidationException("Не удалось извлечь срок годности из токена", e);
        }
    }

    private String createJWE(String baseJwt, String encryptedPayload, String jwtId) throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .keyID(jwtId)
                .type(new JOSEObjectType("JWE"))
                .build();

        JSONObject jwePayload = new JSONObject()
                .appendField("jwt", baseJwt)
                .appendField("encrypted_data", encryptedPayload)
                .appendField("timestamp", System.currentTimeMillis());

        JWEObject jweObject = new JWEObject(header, new Payload(jwePayload.toString()));
        jweObject.encrypt(new DirectEncrypter(encryptionKey.getEncoded()));

        return jweObject.serialize();
    }

    private String encryptSensitiveData(SensitivePayload payload) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String jsonData = mapper.writeValueAsString(payload);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);

        byte[] encryptedData = cipher.doFinal(jsonData.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();

        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
    }

    private SensitivePayload decryptSensitiveData(String encryptedData) throws Exception {
        byte[] combined = Base64.getUrlDecoder().decode(encryptedData);

        byte[] iv = new byte[12];
        byte[] encrypted = new byte[combined.length - 12];
        System.arraycopy(combined, 0, iv, 0, 12);
        System.arraycopy(combined, 12, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, gcmSpec);

        byte[] decryptedData = cipher.doFinal(encrypted);
        String jsonData = new String(decryptedData, StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(jsonData, SensitivePayload.class);
    }

    private void validateSecurityConstraints(Claims claims, SensitivePayload sensitiveData) {
        if (claims.getExpiration().before(new Date())) {
            throw new TokenValidationException("Срок действия токена истек");
        }

        if (sensitiveData.getFingerprint() == null || sensitiveData.getFingerprint().isEmpty()) {
            throw new TokenValidationException("Недопустимый отпечаток пальца");
        }
    }

    private String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    private String generateFingerprint(User user) {
        try {
            String data = user.getLogin() + user.getEmail() + System.currentTimeMillis();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }
}
