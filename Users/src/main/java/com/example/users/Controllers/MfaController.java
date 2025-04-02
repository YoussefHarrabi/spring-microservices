package com.example.users.Controllers;


import com.example.users.Entity.User;
import com.example.users.Repository.UserRepository;
import com.example.users.Services.UserServices.MfaService;
import com.example.users.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final UserRepository userRepository;
    private final MfaService mfaService;
    private final JwtUtils jwtUtils;

    @GetMapping("/setup")
    public ResponseEntity<?> setupMfa(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Generate secret
            String secret = mfaService.generateNewSecret();

            // Save MFA info (not enabled yet)
            mfaService.createOrUpdateMfaInfo(user, secret, false);

            // Generate QR code
            String qrCodeImage = mfaService.generateQrCodeImageUri(secret, user.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("secret", secret);
            response.put("qrCodeImage", qrCodeImage);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error setting up MFA: " + e.getMessage()));
        }
    }

    @PostMapping("/enable")
    public ResponseEntity<?> enableMfa(@RequestHeader("Authorization") String authHeader,
                                       @RequestBody Map<String, String> request) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            String code = request.get("code");

            // Get MFA secret
            String secret = mfaService.getSecretIfExists(user);
            if (secret == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("message", "MFA setup not initiated for this user"));
            }

            // Verify code
            if (!mfaService.verifyCode(code, secret)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Invalid verification code"));
            }

            // Enable MFA
            mfaService.enableMfa(user);

            return ResponseEntity.ok(Map.of("message", "MFA enabled successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error enabling MFA: " + e.getMessage()));
        }
    }

    @PostMapping("/disable")
    public ResponseEntity<?> disableMfa(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Disable MFA
            mfaService.disableMfa(user);

            return ResponseEntity.ok(Map.of("message", "MFA disabled successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error disabling MFA: " + e.getMessage()));
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> getMfaStatus(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Check if MFA is enabled
            boolean mfaEnabled = mfaService.isMfaEnabled(user);

            return ResponseEntity.ok(Map.of("enabled", mfaEnabled));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error getting MFA status: " + e.getMessage()));
        }
    }
}