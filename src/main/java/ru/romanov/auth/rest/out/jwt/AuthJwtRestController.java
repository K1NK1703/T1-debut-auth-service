package ru.romanov.auth.rest.out.jwt;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PostMapping;
import ru.romanov.auth.dto.request.LoginRequestDTO;
import ru.romanov.auth.dto.request.RefreshTokenRequestDTO;
import ru.romanov.auth.dto.request.RegisterRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.AuthResponseDTO;
import ru.romanov.auth.service.AuthService;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
@RequiredArgsConstructor
@ConditionalOnProperty(name = "jwe.enabled", havingValue = "false")
public class AuthJwtRestController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO> registerUser(@Valid @RequestBody RegisterRequestDTO registerRequest) {
        ApiResponseDTO response = authService.registerUser(registerRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequest) {
        AuthResponseDTO response = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        AuthResponseDTO response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO> logoutUser(@RequestBody(required = false) RefreshTokenRequestDTO request) {
        String refreshToken = request != null ? request.refreshToken() : null;
        ApiResponseDTO response = authService.logout(refreshToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/revoke")
    public ResponseEntity<ApiResponseDTO> revokeToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        ApiResponseDTO response = authService.revokeToken(request.refreshToken());
        return ResponseEntity.ok(response);
    }
}
