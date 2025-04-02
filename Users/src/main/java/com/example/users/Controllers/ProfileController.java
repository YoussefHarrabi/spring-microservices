package com.example.users.Controllers;

import com.example.users.Entity.User;
import com.example.users.Repository.UserRepository;
import com.example.users.Services.UserServices.MfaService;
import com.example.users.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/profile")
@RequiredArgsConstructor
public class ProfileController {

    private final UserRepository userRepository;
    private final MfaService mfaService;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    /**
     * Get the current user profile information
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUserProfile(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Check if MFA is enabled
            boolean mfaEnabled = mfaService.isMfaEnabled(user);

            // Build response
            Map<String, Object> response = new HashMap<>();
            response.put("id", user.getId());
            response.put("firstName", user.getFirstName());
            response.put("lastName", user.getLastName());
            response.put("email", user.getEmail());
            response.put("birthday", user.getBirthday());
            response.put("phoneNumber", user.getPhoneNumber());
            response.put("address", user.getAddress());
            response.put("roles", user.getRoles());
            response.put("createdAt", user.getCreatedAt());
            response.put("updatedAt", user.getUpdatedAt());
            response.put("mfaEnabled", mfaEnabled);

            // System information
            response.put("currentDateTime", getCurrentUtcDateTime());
            response.put("username", user.getFirstName() + user.getLastName());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error fetching user profile: " + e.getMessage()));
        }
    }

    /**
     * Update basic profile information
     */
    @PutMapping("/me")
    public ResponseEntity<?> updateProfile(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, Object> updates) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Update fields if provided
            if (updates.containsKey("firstName")) {
                user.setFirstName((String) updates.get("firstName"));
            }

            if (updates.containsKey("lastName")) {
                user.setLastName((String) updates.get("lastName"));
            }

            if (updates.containsKey("phoneNumber")) {
                user.setPhoneNumber((String) updates.get("phoneNumber"));
            }

            if (updates.containsKey("address")) {
                user.setAddress((String) updates.get("address"));
            }

            // Save updated user
            User updatedUser = userRepository.save(user);

            // Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Profile updated successfully");
            response.put("user", Map.of(
                    "id", updatedUser.getId(),
                    "firstName", updatedUser.getFirstName(),
                    "lastName", updatedUser.getLastName(),
                    "email", updatedUser.getEmail(),
                    "phoneNumber", updatedUser.getPhoneNumber(),
                    "address", updatedUser.getAddress()
            ));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error updating profile: " + e.getMessage()));
        }
    }

    /**
     * Change password
     */
    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, String> passwords) {
        try {
            String currentPassword = passwords.get("currentPassword");
            String newPassword = passwords.get("newPassword");

            if (currentPassword == null || newPassword == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("message", "Current password and new password are required"));
            }

            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            // Verify current password
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Current password is incorrect"));
            }

            // Update password
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);

            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error changing password: " + e.getMessage()));
        }
    }

    /**
     * Get system information
     */
    @GetMapping("/system-info")
    public ResponseEntity<?> getSystemInfo(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // Find user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

            Map<String, Object> systemInfo = new HashMap<>();
            systemInfo.put("currentDateTime", getCurrentUtcDateTime());
            systemInfo.put("username", user.getFirstName() + user.getLastName());
            systemInfo.put("serverVersion", "1.0.0");

            return ResponseEntity.ok(systemInfo);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error getting system information: " + e.getMessage()));
        }
    }

    /**
     * Helper method to get current UTC datetime in the required format: 2025-03-06 05:44:54
     */
    private String getCurrentUtcDateTime() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return now.format(formatter);
    }

    /**
     * Get login activity (placeholder implementation since you'd need an actual activity tracking table)
     */
    @GetMapping("/login-activity")
    public ResponseEntity<?> getLoginActivity(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            String token = authHeader.replace("Bearer ", "");
            Long userId = jwtUtils.extractUserId(token);

            // You would typically retrieve this from a database table that logs login events
            // This is a placeholder implementation
            Map<String, Object> activity = new HashMap<>();
            activity.put("user_id", userId);
            activity.put("recent_logins", Map.of(
                    "last_login", getCurrentUtcDateTime(),
                    "last_login_ip", "192.168.1.1",
                    "login_count_last_30_days", 5
            ));

            return ResponseEntity.ok(activity);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error fetching login activity: " + e.getMessage()));
        }
    }
}