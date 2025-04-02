package com.example.users.security;


import com.example.users.Enum.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    private final Key SECRET_KEY;



    public JwtUtils(@Value("${jwt.secret}") String secret) {
        this.SECRET_KEY = Keys.hmacShaKeyFor(Base64.getEncoder().encode(secret.getBytes()));
    }

    // Method to generate JWT Token with email, roles, and userId
    public String generateToken(String email, Set<Role> roles, Long userId) {
        List<String> roleNames = roles.stream().map(Enum::name).collect(Collectors.toList()); // Convert Set<Role> to List<String>

        return Jwts.builder()
                .setSubject(email) // Use email as unique identifier
                .claim("roles", roleNames) // Store roles as a list of strings
                .claim("id", userId) // Store userId
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours expiration
                .signWith(SECRET_KEY)
                .compact();
    }


    // Method to validate the token
    public boolean validateToken(String token, String email) {
        try {
            String extractedEmail = extractUsername(token);
            return (email.equals(extractedEmail) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }


    // Extract the claims from the token
    public Claims extractClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    // Extract the username (email) from the token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // Extract roles from the token
    public Set<Role> extractRoles(String token) {
        return (Set<Role>) extractClaims(token).get("roles");
    }

    // Extract the user ID from the token
    public Long extractUserId(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(token)
                    .getBody();

            // Extract the userId from the "id" claim, not from the subject
            return Long.parseLong(claims.get("id").toString());
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }
    public String generateLongLifeToken(String email, Set<Role> roles, Long userId) {
        List<String> roleNames = roles.stream().map(Enum::name).collect(Collectors.toList());

        return Jwts.builder()
                .setSubject(email)
                .claim("roles", roleNames)
                .claim("id", userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365)) // 1 year expiration
                .signWith(SECRET_KEY)
                .compact();
    }


    // Check if the token is expired
    private boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

}

