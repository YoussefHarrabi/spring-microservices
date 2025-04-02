package com.example.users.Entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private LocalDateTime expiryDateTime;

    private boolean used;

    @PrePersist
    protected void onCreate() {
        token = UUID.randomUUID().toString();
        expiryDateTime = LocalDateTime.now().plusHours(24); // Token valid for 24 hours
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDateTime);
    }
}