package com.example.users.Controllers;

import com.example.users.Entity.User;
import com.example.users.Enum.Role;
import com.example.users.Repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@CrossOrigin
@RequestMapping("/jwt-reset")
@RequiredArgsConstructor
public class JwtResetController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secretString;

    @GetMapping("/system-time")
    public ResponseEntity<?> getSystemTime() {
        Map<String, Object> response = new HashMap<>();
        Date now = new Date();
        response.put("currentTime", now);
        response.put("currentTimeFormatted", now.toString());
        response.put("currentTimeMillis", now.getTime());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/generate-token")
    public ResponseEntity<?> generateToken(@RequestBody Map<String, String> credentials) {
        try {
            String email = credentials.get("email");
            String password = credentials.get("password");

            // Find user
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            // Verify password
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new RuntimeException("Invalid password");
            }

            // Generate fresh token with current time
            String token = generateFreshJwt(user);

            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("generatedAt", new Date());
            response.put("user", Map.of(
                    "id", user.getId(),
                    "email", user.getEmail(),
                    "roles", user.getRoles().stream().map(Enum::name).collect(Collectors.toList())
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", true,
                    "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");

            // Parse token without validation
            Key key = Keys.hmacShaKeyFor(Base64.getEncoder().encode(secretString.getBytes()));
            var claims = Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(token)
                    .getBody();

            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("subject", claims.getSubject());
            response.put("issuedAt", claims.getIssuedAt());
            response.put("expiration", claims.getExpiration());
            response.put("currentTime", new Date());
            response.put("roles", claims.get("roles"));
            response.put("id", claims.get("id"));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false,
                    "error", e.getMessage()
            ));
        }
    }

    private String generateFreshJwt(User user) {
        Key key = Keys.hmacShaKeyFor(Base64.getEncoder().encode(secretString.getBytes()));

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 1000 * 60 * 60 * 24); // 24 hours

        List<String> roleNames = user.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toList());

        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("roles", roleNames)
                .claim("id", user.getId())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}