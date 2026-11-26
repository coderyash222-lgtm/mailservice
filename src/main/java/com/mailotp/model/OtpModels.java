package com.mailotp.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class OtpModels {

    private OtpModels() {}

    public record SendOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Provide a valid email address")
        String email,

        @Size(max = 64, message = "App name must be 64 characters or fewer")
        String appName
    ) {}

    public record SendOtpResponse(
        boolean sent,
        String email,
        int expiresInSeconds,
        int cooldownSeconds,
        Instant expiresAt,
        String message
    ) {}

    public record VerifyOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Provide a valid email address")
        String email,

        @NotBlank(message = "OTP code is required")
        @Pattern(regexp = "^[0-9]{6}$", message = "OTP must be a 6-digit numeric code")
        String otp
    ) {}

    public record VerifyOtpResponse(
        boolean verified,
        String email,
        String status,
        int remainingAttempts,
        String message
    ) {}

    public record OtpStatusResponse(
        String email,
        boolean active,
        long expiresInSeconds,
        long resendAvailableInSeconds,
        int remainingAttempts
    ) {}

    public record ApiError(
        int status,
        String error,
        String message,
        Instant timestamp
    ) {}
}
