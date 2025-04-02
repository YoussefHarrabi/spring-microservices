package com.example.users.Entity;


import com.example.users.Enum.IdentityType;
import com.example.users.Enum.Role;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private LocalDate birthday;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private IdentityType identityType;

    @Column(unique = true, nullable = false)
    private String numberOfIdentity;

    @Column(nullable = false)
    private String phoneNumber;

    private String address;
    // Add the password field
    @Column(nullable = false)
    private String password;

    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<Role> roles;

    @Column(nullable = false, updatable = false)
    private LocalDate createdAt;

    private LocalDate updatedAt;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private MfaInfo mfaInfo;

    // You can add this method for convenience, but it's optional
    public boolean isMfaEnabled() {
        return mfaInfo != null && mfaInfo.isEnabled();
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDate.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDate.now();
    }
}