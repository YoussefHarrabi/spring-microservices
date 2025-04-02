package com.example.users.Services.UserServices;


import com.example.users.Entity.User;
import com.example.users.Enum.Role;
import com.example.users.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User createUser(User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new IllegalStateException("Email already in use.");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
    public User updateUserRole(Long id, String role) {
        User user = getUserById(id).get();
        // Create a new mutable set instead of using Set.of() which creates an immutable set
        Set<Role> roles = new HashSet<>();

        // Add the appropriate role
        if ("ADMIN".equals(role)) {
            roles.add(Role.ADMIN);
        } else if ("CLIENT".equals(role)) {
            roles.add(Role.CLIENT);
        } else {
            // Default to CLIENT if role is not recognized
            roles.add(Role.CLIENT);
        }

        // Set the new mutable set of roles
        user.setRoles(roles);

        return userRepository.save(user);
    }
    public User updateUser(Long id, User updatedUser) {
        return userRepository.findById(id)
                .map(user -> {
                    user.setFirstName(updatedUser.getFirstName());
                    user.setLastName(updatedUser.getLastName());
                    user.setEmail(updatedUser.getEmail());
                    user.setBirthday(updatedUser.getBirthday());
                    user.setIdentityType(updatedUser.getIdentityType());
                    user.setNumberOfIdentity(updatedUser.getNumberOfIdentity());
                    user.setPhoneNumber(updatedUser.getPhoneNumber());
                    user.setRoles(updatedUser.getRoles());
                    return userRepository.save(user);
                })
                .orElseThrow(() -> new IllegalStateException("User not found."));
    }

    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalStateException("User not found.");
        }
        userRepository.deleteById(id);
    }
}