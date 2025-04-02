package com.example.users.Services.UserServices;




import com.example.users.Entity.User;
import com.example.users.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository; // Ensure this repository exists

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This is still the method Spring Security uses
        // Now we search by the identity number (numberOfIdentity)
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), // Use email as the username for authentication
                user.getPassword(),
                user.getRoles().stream()
                        .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority(role.name()))
                        .toList()
        );
    }

    // This is your custom method, used internally if you want to load a user by identity number
    public UserDetails loadUserByIdentityNumber(String identityNumber) throws UsernameNotFoundException {
        User user = userRepository.findByNumberOfIdentity(identityNumber)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), // Use email as the username for authentication
                user.getPassword(),
                user.getRoles().stream()
                        .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority(role.name()))
                        .toList()
        );
    }
}