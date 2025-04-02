package com.example.users.Controllers;

import com.example.users.Entity.User;
import com.example.users.Enum.Role;
import com.example.users.Repository.UserRepository;
import com.example.users.Services.UserServices.MfaService;
import com.example.users.security.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@CrossOrigin
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtService;
    private final MfaService mfaService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> user) {
        String email = user.get("email");
        String password = user.get("password");

        try {
            // Fetch user from the database
            User dbUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Validate the password
            if (!passwordEncoder.matches(password, dbUser.getPassword())) {
                throw new RuntimeException("Invalid password");
            }

            // Check if MFA is enabled for this user
            boolean mfaEnabled = mfaService.isMfaEnabled(dbUser);

            Map<String, Object> response = new HashMap<>();

            // If MFA is not enabled, generate and return JWT
            if (!mfaEnabled) {
                // Extract roles
                Set<Role> roles = dbUser.getRoles();

                // Generate token
                String token = jwtService.generateToken(email, roles, dbUser.getId());

                // Return token in the response
                response.put("token", token);
                response.put("requiresMfa", false);
                return ResponseEntity.ok(response);
            }

            // If MFA is enabled, return flag indicating MFA is required
            response.put("requiresMfa", true);
            response.put("email", email);  // Send back email for 2nd phase
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody Map<String, String> mfaRequest) {
        try {
            String email = mfaRequest.get("email");
            String code = mfaRequest.get("code");

            // Find user
            User dbUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            // Get MFA secret
            String secret = mfaService.getSecretIfExists(dbUser);
            if (secret == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("message", "MFA not set up for this user"));
            }

            // Verify code
            if (!mfaService.verifyCode(code, secret)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Invalid MFA code"));
            }

            // Extract roles
            Set<Role> roles = dbUser.getRoles();

            // Generate token
            String token = jwtService.generateToken(email, roles, dbUser.getId());

            // Return token in the response
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("requiresMfa", false);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "An error occurred: " + e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody User user) {
        // Check if email is already in use
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("message", "Email is already in use"));
        }

        // Encode the password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Set default role (USER)
        user.setRoles(Set.of(Role.CLIENT));

        // Save the user
        User savedUser = userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }

    @PostMapping("/register-admin")
    public ResponseEntity<?> registerAdmin(@Valid @RequestBody User user) {
        // Check if email is already in use
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("message", "Email is already in use"));
        }

        // Encode the password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Set admin role
        user.setRoles(Set.of(Role.ADMIN));

        // Save the user
        User savedUser = userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }
    // Add this method to your AuthController class
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from header
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Invalid or missing Authorization header"));
            }

            String token = authHeader.substring(7).trim();

            // Extract claims from the existing token
            Claims claims = jwtService.extractClaims(token);
            String email = claims.getSubject();
            List<String> roleStrings = (List<String>) claims.get("roles");
            Long userId = Long.parseLong(claims.get("id").toString());

            // Convert role strings back to Role enum
            Set<Role> roles = roleStrings.stream()
                    .map(Role::valueOf)
                    .collect(Collectors.toSet());

            // Generate a new token
            String newToken = jwtService.generateToken(email, roles, userId);

            return ResponseEntity.ok(Map.of("token", newToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", e.getMessage()));
        }
    }
    // Add this method to your AuthController class
    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");

            // Extract claims to validate token
            Claims claims = jwtService.extractClaims(token);
            String email = claims.getSubject();
            Long userId = Long.parseLong(claims.get("id").toString());
            Date expiration = claims.getExpiration();

            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("email", email);
            response.put("userId", userId);
            response.put("expiration", expiration);
            response.put("currentTime", new Date());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "valid", false,
                            "error", e.getMessage()
                    ));
        }
    }
    @PostMapping("/generate-fresh-token")
    public ResponseEntity<?> generateFreshToken(@RequestBody Map<String, String> loginRequest) {
        try {
            String email = loginRequest.get("email");
            String password = loginRequest.get("password");

            // Fetch user from the database
            User dbUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Validate the password
            if (!passwordEncoder.matches(password, dbUser.getPassword())) {
                throw new RuntimeException("Invalid password");
            }

            // Extract roles
            Set<Role> roles = dbUser.getRoles();

            // Generate a new token with a very long expiration for testing
            String token = jwtService.generateLongLifeToken(email, roles, dbUser.getId());

            return ResponseEntity.ok(Map.of("token", token));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", e.getMessage()));
        }
    }
    @GetMapping("/system-time")
    public ResponseEntity<?> getSystemTime() {
        Date currentTime = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");

        Map<String, Object> response = new HashMap<>();
        response.put("serverTime", currentTime);
        response.put("formattedTime", formatter.format(currentTime));

        return ResponseEntity.ok(response);
    }
}