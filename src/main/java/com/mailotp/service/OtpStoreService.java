package com.mailotp.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class OtpStoreService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final int expiryMinutes;
    private final int maxAttempts;
    private final int cooldownSeconds;
    private final String serverPepper;
    private final Map<String, OtpRecord> store = new ConcurrentHashMap<>();

    public OtpStoreService(
        @Value("${otp.expiry-minutes:5}") int expiryMinutes,
        @Value("${otp.max-attempts:5}") int maxAttempts,
        @Value("${otp.cooldown-seconds:30}") int cooldownSeconds,
        @Value("${otp.secret:}") String configuredSecret
    ) {
        this.expiryMinutes = Math.max(1, expiryMinutes);
        this.maxAttempts = Math.max(1, maxAttempts);
        this.cooldownSeconds = Math.max(0, cooldownSeconds);
        if (configuredSecret != null && !configuredSecret.isBlank()) {
            this.serverPepper = configuredSecret;
        } else {
            byte[] randomBytes = new byte[32];
            SECURE_RANDOM.nextBytes(randomBytes);
            this.serverPepper = Base64.getEncoder().encodeToString(randomBytes);
        }
    }

    public IssuedOtp issueOtp(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        Instant now = Instant.now();

        OtpRecord existing = store.get(email);
        if (existing != null && !existing.isExpired(now)) {
            long elapsedSeconds = Duration.between(existing.issuedAt(), now).getSeconds();
            if (elapsedSeconds < cooldownSeconds) {
                long waitSeconds = cooldownSeconds - elapsedSeconds;
                throw new CooldownException(waitSeconds);
            }
        }

        String code = String.format("%06d", SECURE_RANDOM.nextInt(1_000_000));
        byte[] saltBytes = new byte[16];
        SECURE_RANDOM.nextBytes(saltBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        byte[] hash = hashCode(email, code, salt);

        Instant expiresAt = now.plusSeconds((long) expiryMinutes * 60);
        store.put(email, new OtpRecord(salt, hash, now, expiresAt, 0));

        return new IssuedOtp(email, code, expiryMinutes * 60, cooldownSeconds, expiresAt);
    }

    public void revokeOtp(String rawEmail) {
        if (rawEmail != null && !rawEmail.isBlank()) {
            store.remove(normalizeEmail(rawEmail));
        }
    }

    public VerificationResult verifyOtp(String rawEmail, String candidateOtp) {
        String email = normalizeEmail(rawEmail);
        Instant now = Instant.now();
        OtpRecord record = store.get(email);

        if (record == null) {
            return new VerificationResult(false, "NOT_FOUND", 0, "No active verification code found for this email.");
        }

        if (record.isExpired(now)) {
            store.remove(email, record);
            return new VerificationResult(false, "EXPIRED", 0, "Verification code has expired. Request a new code.");
        }

        if (record.attempts() >= maxAttempts) {
            store.remove(email, record);
            return new VerificationResult(false, "LOCKED", 0, "Maximum verification attempts exceeded. Request a new code.");
        }

        byte[] candidateHash = hashCode(email, candidateOtp.trim(), record.salt());
        boolean matches = MessageDigest.isEqual(candidateHash, record.hash());

        if (matches) {
            store.remove(email, record);
            return new VerificationResult(true, "VERIFIED", 0, "Email address verified successfully.");
        }

        int nextAttempts = record.attempts() + 1;
        int remaining = Math.max(0, maxAttempts - nextAttempts);
        if (remaining == 0) {
            store.remove(email, record);
            return new VerificationResult(false, "LOCKED", 0, "Invalid code. Maximum attempts exceeded.");
        }

        store.put(email, new OtpRecord(record.salt(), record.hash(), record.issuedAt(), record.expiresAt(), nextAttempts));
        return new VerificationResult(false, "INVALID", remaining, "Invalid verification code.");
    }

    public StatusSnapshot getStatus(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        Instant now = Instant.now();
        OtpRecord record = store.get(email);

        if (record == null || record.isExpired(now)) {
            if (record != null) {
                store.remove(email, record);
            }
            return new StatusSnapshot(email, false, 0, 0, 0);
        }

        long expiresIn = Math.max(0, Duration.between(now, record.expiresAt()).getSeconds());
        long elapsed = Duration.between(record.issuedAt(), now).getSeconds();
        long resendWait = Math.max(0, cooldownSeconds - elapsed);
        int remainingAttempts = Math.max(0, maxAttempts - record.attempts());

        return new StatusSnapshot(email, true, expiresIn, resendWait, remainingAttempts);
    }

    @Scheduled(fixedDelayString = "${otp.cleanup-interval-ms:60000}")
    public void purgeExpiredEntries() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
    }

    private byte[] hashCode(String email, String code, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String payload = email + ":" + salt + ":" + code + ":" + serverPepper;
            return digest.digest(payload.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", ex);
        }
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private record OtpRecord(
        String salt,
        byte[] hash,
        Instant issuedAt,
        Instant expiresAt,
        int attempts
    ) {
        boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }
    }

    public record IssuedOtp(
        String email,
        String code,
        int expiresInSeconds,
        int cooldownSeconds,
        Instant expiresAt
    ) {}

    public record VerificationResult(
        boolean verified,
        String status,
        int remainingAttempts,
        String message
    ) {}

    public record StatusSnapshot(
        String email,
        boolean active,
        long expiresInSeconds,
        long resendAvailableInSeconds,
        int remainingAttempts
    ) {}

    public static class CooldownException extends RuntimeException {
        private final long retryAfterSeconds;

        public CooldownException(long retryAfterSeconds) {
            super("Please wait " + retryAfterSeconds + " seconds before requesting another code.");
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public long getRetryAfterSeconds() {
            return retryAfterSeconds;
        }
    }
}
