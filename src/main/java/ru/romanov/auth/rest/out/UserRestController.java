package ru.romanov.auth.rest.out;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import ru.romanov.auth.dto.request.ChangePasswordRequestDTO;
import ru.romanov.auth.dto.request.UpdateProfileRequestDTO;
import ru.romanov.auth.dto.response.ApiResponseDTO;
import ru.romanov.auth.dto.response.AuthResponseDTO;
import ru.romanov.auth.model.entity.User;
import ru.romanov.auth.service.UserService;
import ru.romanov.auth.util.UserSecurity;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "*", maxAge = 3600)
@RequiredArgsConstructor
public class UserRestController {

    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<AuthResponseDTO.UserInfo> getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserSecurity userSecurity = (UserSecurity) authentication.getPrincipal();

        User user = userSecurity.user();

        AuthResponseDTO.UserInfo userInfo = new AuthResponseDTO.UserInfo(
                user.getId(), user.getLogin(), user.getEmail(), user.getRoles());

        return ResponseEntity.ok(userInfo);
    }

    @PutMapping("/change-password")
    public ResponseEntity<ApiResponseDTO> changePassword(@Valid @RequestBody ChangePasswordRequestDTO request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentLogin = authentication.getName();

        ApiResponseDTO response = userService.changePassword(
                currentLogin,
                request.currentPassword(),
                request.newPassword()
        );

        return ResponseEntity.ok(response);
    }

    @PutMapping("/profile")
    public ResponseEntity<ApiResponseDTO> updateProfile(@Valid @RequestBody UpdateProfileRequestDTO request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentLogin = authentication.getName();

        ApiResponseDTO response = userService.updateProfile(
                currentLogin,
                request.login(),
                request.email()
        );

        return ResponseEntity.ok(response);
    }
}
