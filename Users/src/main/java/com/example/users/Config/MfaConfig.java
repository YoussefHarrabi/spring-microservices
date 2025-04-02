package com.example.users.Config;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MfaConfig {

    @Bean
    public SecretGenerator secretGenerator() {
        return new DefaultSecretGenerator(32);
    }

    @Bean
    public CodeVerifier codeVerifier() {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        DefaultCodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        // Allow codes from 30 seconds ago and 30 seconds in the future
        codeVerifier.setAllowedTimePeriodDiscrepancy(1);
        return codeVerifier;
    }
}