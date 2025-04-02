package com.example.users.Controllers;


import com.example.users.Entity.PasswordResetToken;
import com.example.users.Entity.User;
import com.example.users.Repository.PasswordResetTokenRepository;
import com.example.users.Repository.UserRepository;
import com.example.users.Services.UserServices.EmailService;
import com.example.users.Services.UserServices.EmailTemplateService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Optional;

@RestController
@CrossOrigin
@RequestMapping("/api/auth/password")
@RequiredArgsConstructor
public class PasswordResetController {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailService emailService;
    private final EmailTemplateService emailTemplateService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/forgot")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            // Don't reveal that the email doesn't exist for security reasons
            return ResponseEntity.ok().body(Map.of("message", "If your email is registered, you will receive a reset link"));
        }

        User user = userOpt.get();

        // Check if a token already exists for this user and delete it
        tokenRepository.findByUser(user).ifPresent(tokenRepository::delete);

        // Create new token
        PasswordResetToken token = PasswordResetToken.builder()
                .user(user)
                .build();
        tokenRepository.save(token);

        // Reset link for frontend
        String resetLink = "http://localhost:4200/client/reset-password?token=" + token.getToken();
        String expiryTime = token.getExpiryDateTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        try {
            // Create HTML content directly
            String emailContent =
                    "<!DOCTYPE html>" +
                            "<html>" +
                            "<head>" +
                            "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />" +
                            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>" +
                            "    <style>" +
                            "        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; margin: 0; padding: 0; }" +
                            "        .container { max-width: 600px; margin: 20px auto; background-color: #f9f9f9; border-radius: 6px; overflow: hidden; box-shadow: 0 3px 10px rgba(0,0,0,0.1); }" +
                            "        .header { text-align: center; padding: 25px 0; background: linear-gradient(135deg, #0062E6 0%, #33AEFF 100%); color: white; }" +
                            "        .header h2 { margin: 0; font-weight: 500; letter-spacing: 0.5px; }" +
                            "        .content { background-color: white; padding: 40px; border-radius: 0 0 5px 5px; }" +
                            "        .content h3 { color: #2c3e50; margin-top: 0; }" +
                            "        .button-container { text-align: center; margin: 30px 0; }" +
                            "        .button { display: inline-block; background: linear-gradient(135deg, #0062E6 0%, #33AEFF 100%); color: white !important; text-decoration: none; " +
                            "                  padding: 12px 30px; border-radius: 50px; font-weight: 500; letter-spacing: 0.5px; transition: all 0.3s; box-shadow: 0 4px 6px rgba(50, 50, 93, .11), 0 1px 3px rgba(0, 0, 0, .08); }" +
                            "        .reset-link { margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; word-break: break-all; color: #007bff; }" +
                            "        .expiry-notice { margin-top: 20px; padding: 10px 15px; background-color: #fff4e5; border-left: 4px solid #ffa726; font-style: italic; color: #666; }" +
                            "        .footer { text-align: center; margin-top: 0; padding: 20px; color: #666; font-size: 12px; background-color: #f9f9f9; }" +
                            "        .divider { height: 1px; background-color: #e9ecef; margin: 30px 0; }" +
                            "    </style>" +
                            "</head>" +
                            "<body>" +
                            "    <div class='container'>" +
                            "        <div class='header'>" +
                            "            <h2>Password Reset Request</h2>" +
                            "        </div>" +
                            "        <div class='content'>" +
                            "            <h3>Hello " + user.getFirstName() + ",</h3>" +
                            "            <p>We received a request to reset your password for your account. If you didn't make this request, you can safely ignore this email.</p>" +
                            "            <div class='button-container'>" +
                            "                <a href='" + resetLink + "' class='button' style='color: white;'>Reset Your Password</a>" +
                            "            </div>" +
                            "            <p>If the button above doesn't work, copy and paste the following link into your browser:</p>" +
                            "            <div class='reset-link'>" +
                            "                <a href='" + resetLink + "'>" + resetLink + "</a>" +
                            "            </div>" +
                            "            <div class='expiry-notice'>" +
                            "                <p><strong>Note:</strong> This link will expire on " + expiryTime + ".</p>" +
                            "            </div>" +
                            "            <div class='divider'></div>" +
                            "            <p>If you didn't request a password reset, please ensure your account is secure by checking your account details.</p>" +
                            "            <p>Best regards,<br/><strong>Your Application Team</strong></p>" +
                            "        </div>" +
                            "        <div class='footer'>" +
                            "            <p>&copy; " + java.time.Year.now().getValue() + " Your Company. All rights reserved.</p>" +
                            "            <p>This is an automated message, please do not reply to this email.</p>" +
                            "        </div>" +
                            "    </div>" +
                            "</body>" +
                            "</html>";

            // Send HTML email
            emailService.sendHtmlMessage(user.getEmail(), "Password Reset Request", emailContent);

            return ResponseEntity.ok().body(Map.of(
                    "message", "If your email is registered, you will receive a reset link",
                    "success", true
            ));
        } catch (MessagingException e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "message", "Error sending email: " + e.getMessage(),
                    "success", false
            ));
        }
    }

    // The rest of the controller methods remain unchanged
    @PostMapping("/reset")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("password");

        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(token);
        if (tokenOpt.isEmpty() || tokenOpt.get().isUsed() || tokenOpt.get().isExpired()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired token"));
        }

        PasswordResetToken resetToken = tokenOpt.get();
        User user = resetToken.getUser();

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Mark token as used
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        return ResponseEntity.ok().body(Map.of("message", "Password has been reset successfully"));
    }

    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestParam String token) {
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(token);

        if (tokenOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "message", "Token not found"));
        }

        PasswordResetToken resetToken = tokenOpt.get();

        if (resetToken.isUsed()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "message", "Token already used"));
        }

        if (resetToken.isExpired()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "message", "Token expired"));
        }

        return ResponseEntity.ok().body(Map.of(
                "valid", true,
                "email", resetToken.getUser().getEmail(),
                "expiryDateTime", resetToken.getExpiryDateTime().toString()
        ));
    }
    // Add this method for development testing only
    @GetMapping("/preview-email")
    public ResponseEntity<String> previewEmail() {
        // Dummy data for preview
        String resetLink = "http://localhost:4200/client/reset-password?token=sample-token-12345";
        String firstName = "John";
        String expiryTime = java.time.LocalDateTime.now().plusDays(1).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        String emailContent =
                "<!DOCTYPE html>" +
                        "<html>" +
                        "<head>" +
                        "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />" +
                        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>" +
                        "    <style>" +
                        "        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; margin: 0; padding: 0; }" +
                        "        .container { max-width: 600px; margin: 20px auto; background-color: #f9f9f9; border-radius: 6px; overflow: hidden; box-shadow: 0 3px 10px rgba(0,0,0,0.1); }" +
                        "        .header { text-align: center; padding: 25px 0; background: linear-gradient(135deg, #0062E6 0%, #33AEFF 100%); color: white; }" +
                        "        .header h2 { margin: 0; font-weight: 500; letter-spacing: 0.5px; }" +
                        "        .content { background-color: white; padding: 40px; border-radius: 0 0 5px 5px; }" +
                        "        .content h3 { color: #2c3e50; margin-top: 0; }" +
                        "        .button-container { text-align: center; margin: 30px 0; }" +
                        "        .button { display: inline-block; background: linear-gradient(135deg, #0062E6 0%, #33AEFF 100%); color: white !important; text-decoration: none; " +
                        "                  padding: 12px 30px; border-radius: 50px; font-weight: 500; letter-spacing: 0.5px; transition: all 0.3s; box-shadow: 0 4px 6px rgba(50, 50, 93, .11), 0 1px 3px rgba(0, 0, 0, .08); }" +
                        "        .reset-link { margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; word-break: break-all; color: #007bff; }" +
                        "        .expiry-notice { margin-top: 20px; padding: 10px 15px; background-color: #fff4e5; border-left: 4px solid #ffa726; font-style: italic; color: #666; }" +
                        "        .footer { text-align: center; margin-top: 0; padding: 20px; color: #666; font-size: 12px; background-color: #f9f9f9; }" +
                        "        .divider { height: 1px; background-color: #e9ecef; margin: 30px 0; }" +
                        "    </style>" +

                        "</head>" +
                        "<body>" +
                        "    <div class='container'>" +
                        "        <div class='header'>" +
                        "            <h2>Password Reset Request</h2>" +
                        "        </div>" +
                        "        <div class='content'>" +
                        "            <h3>Hello " + firstName + ",</h3>" +
                        "            <p>We received a request to reset your password for your account. If you didn't make this request, you can safely ignore this email.</p>" +
                        "            <div class='button-container'>" +
                        "                <a href='" + resetLink + "' class='button' style='color: white;'>Reset Your Password</a>" +
                        "            </div>" +
                        "            <p>If the button above doesn't work, copy and paste the following link into your browser:</p>" +
                        "            <div class='reset-link'>" +
                        "                <a href='" + resetLink + "'>" + resetLink + "</a>" +
                        "            </div>" +
                        "            <div class='expiry-notice'>" +
                        "                <p><strong>Note:</strong> This link will expire on " + expiryTime + ".</p>" +
                        "            </div>" +
                        "            <div class='divider'></div>" +
                        "            <p>If you didn't request a password reset, please ensure your account is secure by checking your account details.</p>" +
                        "            <p>Best regards,<br/><strong>Your Application Team</strong></p>" +
                        "        </div>" +
                        "        <div class='footer'>" +
                        "            <p>&copy; " + java.time.Year.now().getValue() + " Your Company. All rights reserved.</p>" +
                        "            <p>This is an automated message, please do not reply to this email.</p>" +
                        "        </div>" +
                        "    </div>" +
                        "</body>" +
                        "</html>";

        return ResponseEntity.ok()
                .header("Content-Type", "text/html")
                .body(emailContent);
    }
}