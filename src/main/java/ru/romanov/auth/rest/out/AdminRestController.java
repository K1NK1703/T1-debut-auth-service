package ru.romanov.auth.rest.out;

import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestBody;
import ru.romanov.auth.dto.request.UpdateUserRolesRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.service.TokenService;
import ru.romanov.auth.service.UserService;

import java.util.List;

@RestController
@RequestMapping("/admin")
@CrossOrigin(origins = "*", maxAge = 3600)
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AdminRestController {

    UserService userService;
    TokenService tokenService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<User> getUserById(@PathVariable Long userId) {
        User user = userService.findById(userId);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/users/{userId}/roles")
    public ResponseEntity<ApiResponseDTO> updateUserRoles(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateUserRolesRequestDTO request) {
        ApiResponseDTO response = userService.updateUserRoles(userId, request.roles());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/users/{userId}")
    public ResponseEntity<ApiResponseDTO> deleteUser(@PathVariable Long userId) {
        ApiResponseDTO response = userService.deleteUser(userId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/tokens/active")
    public ResponseEntity<Object> getAllActiveTokens() {
        var tokens = tokenService.getAllActiveTokens();
        return ResponseEntity.ok(new ApiResponseDTO(true, "Активные токены получены", tokens));
    }

    @DeleteMapping("/tokens/cleanup")
    public ResponseEntity<ApiResponseDTO> cleanupExpiredTokens() {
        tokenService.cleanupExpiredTokens();
        return ResponseEntity.ok(new ApiResponseDTO(true, "Истёкшие токены очищены"));
    }

    @DeleteMapping("/users/{userId}/tokens")
    public ResponseEntity<ApiResponseDTO> revokeAllUserTokens(@PathVariable Long userId) {
        User user = userService.findById(userId);
        tokenService.revokeAllUserTokens(user);
        return ResponseEntity.ok(new ApiResponseDTO(true, "Все токены пользователя отозваны"));
    }
}
