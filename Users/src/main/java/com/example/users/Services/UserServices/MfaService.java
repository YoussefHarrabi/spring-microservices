package com.example.users.Services.UserServices;

import com.example.users.Entity.MfaInfo;
import com.example.users.Entity.User;
import com.example.users.Repository.MfaInfoRepository;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final MfaInfoRepository mfaInfoRepository;
    private final SecretGenerator secretGenerator;
    private final CodeVerifier codeVerifier;

    public String generateNewSecret() {
        return secretGenerator.generate();
    }

    public String generateQrCodeImageUri(String secret, String email) {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer("Assurance App")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator qrGenerator = new ZxingPngQrGenerator();
        byte[] imageData;
        try {
            imageData = qrGenerator.generate(data);
        } catch (QrGenerationException e) {
            throw new RuntimeException("Error generating QR code", e);
        }

        return "data:image/png;base64," + Base64.getEncoder().encodeToString(imageData);
    }

    public boolean verifyCode(String code, String secret) {
        return codeVerifier.isValidCode(secret, code);
    }

    @Transactional
    public MfaInfo createOrUpdateMfaInfo(User user, String secret, boolean enabled) {
        Optional<MfaInfo> existingMfaInfo = mfaInfoRepository.findByUser(user);

        if (existingMfaInfo.isPresent()) {
            MfaInfo mfaInfo = existingMfaInfo.get();
            mfaInfo.setSecret(secret);
            mfaInfo.setEnabled(enabled);
            return mfaInfoRepository.save(mfaInfo);
        } else {
            MfaInfo mfaInfo = MfaInfo.builder()
                    .user(user)
                    .secret(secret)
                    .enabled(enabled)
                    .build();
            return mfaInfoRepository.save(mfaInfo);
        }
    }

    @Transactional
    public void enableMfa(User user) {
        Optional<MfaInfo> mfaInfoOpt = mfaInfoRepository.findByUser(user);
        if (mfaInfoOpt.isPresent()) {
            MfaInfo mfaInfo = mfaInfoOpt.get();
            mfaInfo.setEnabled(true);
            mfaInfoRepository.save(mfaInfo);
        }
    }

    @Transactional
    public void disableMfa(User user) {
        Optional<MfaInfo> mfaInfoOpt = mfaInfoRepository.findByUser(user);
        if (mfaInfoOpt.isPresent()) {
            MfaInfo mfaInfo = mfaInfoOpt.get();
            mfaInfo.setEnabled(false);
            mfaInfoRepository.save(mfaInfo);
        }
    }

    public boolean isMfaEnabled(User user) {
        Optional<MfaInfo> mfaInfoOpt = mfaInfoRepository.findByUser(user);
        return mfaInfoOpt.isPresent() && mfaInfoOpt.get().isEnabled();
    }

    public String getSecretIfExists(User user) {
        Optional<MfaInfo> mfaInfoOpt = mfaInfoRepository.findByUser(user);
        return mfaInfoOpt.map(MfaInfo::getSecret).orElse(null);
    }
}