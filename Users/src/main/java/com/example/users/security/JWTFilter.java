package com.example.users.security;

import com.example.users.Services.UserServices.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtil;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    // List of paths that should bypass authentication
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/register-admin",
            "/api/auth/verify-mfa",
            "/api/auth/password",
            "/jwt-reset"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Get the path
        String path = request.getServletPath();

        // Check if it's a public path that should bypass authentication
        if (isPublicPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader("Authorization");

        // Process JWT only for protected paths
        if (token != null && token.startsWith("Bearer ")) {
            try {
                token = token.substring(7);
                String username = jwtUtil.extractUsername(token);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtUtil.validateToken(token, username)) {
                        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (Exception e) {
                // Log the error but don't block the request - let the security context remain empty
                System.err.println("JWT Authentication error: " + e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }
}