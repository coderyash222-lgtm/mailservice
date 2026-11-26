package com.mailotp.controller;

import com.mailotp.model.OtpModels.ApiError;
import com.mailotp.model.OtpModels.OtpStatusResponse;
import com.mailotp.model.OtpModels.SendOtpRequest;
import com.mailotp.model.OtpModels.SendOtpResponse;
import com.mailotp.model.OtpModels.VerifyOtpRequest;
import com.mailotp.model.OtpModels.VerifyOtpResponse;
import com.mailotp.service.MailSenderService;
import com.mailotp.service.OtpStoreService;
import com.mailotp.service.OtpStoreService.CooldownException;
import com.mailotp.service.OtpStoreService.IssuedOtp;
import com.mailotp.service.OtpStoreService.StatusSnapshot;
import com.mailotp.service.OtpStoreService.VerificationResult;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Validated
public class OtpController {

    private static final Logger log = LoggerFactory.getLogger(OtpController.class);

    private final OtpStoreService otpStoreService;
    private final MailSenderService mailSenderService;

    public OtpController(OtpStoreService otpStoreService, MailSenderService mailSenderService) {
        this.otpStoreService = otpStoreService;
        this.mailSenderService = mailSenderService;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "mail-otp-service",
            "timestamp", Instant.now().toString()
        ));
    }

    @PostMapping("/v1/otp/send")
    public ResponseEntity<SendOtpResponse> sendOtp(@Valid @RequestBody SendOtpRequest request) {
        IssuedOtp issued = otpStoreService.issueOtp(request.email());
        try {
            mailSenderService.sendOtpEmail(
                issued.email(),
                issued.code(),
                issued.expiresInSeconds(),
                request.appName()
            );
        } catch (RuntimeException ex) {
            otpStoreService.revokeOtp(issued.email());
            throw ex;
        }

        return ResponseEntity.ok(new SendOtpResponse(
            true,
            issued.email(),
            issued.expiresInSeconds(),
            issued.cooldownSeconds(),
            issued.expiresAt(),
            "Verification code dispatched via JavaMailSender."
        ));
    }

    @PostMapping("/v1/otp/verify")
    public ResponseEntity<VerifyOtpResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        VerificationResult result = otpStoreService.verifyOtp(request.email(), request.otp());
        HttpStatus status = result.verified() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;

        return ResponseEntity.status(status).body(new VerifyOtpResponse(
            result.verified(),
            request.email().trim().toLowerCase(),
            result.status(),
            result.remainingAttempts(),
            result.message()
        ));
    }

    @GetMapping("/v1/otp/status")
    public ResponseEntity<OtpStatusResponse> status(
        @RequestParam @NotBlank @Email(message = "Provide a valid email address") String email
    ) {
        StatusSnapshot snapshot = otpStoreService.getStatus(email);
        return ResponseEntity.ok(new OtpStatusResponse(
            snapshot.email(),
            snapshot.active(),
            snapshot.expiresInSeconds(),
            snapshot.resendAvailableInSeconds(),
            snapshot.remainingAttempts()
        ));
    }

    @ExceptionHandler(CooldownException.class)
    public ResponseEntity<ApiError> handleCooldown(CooldownException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
            .body(new ApiError(429, "TOO_MANY_REQUESTS", ex.getMessage(), Instant.now()));
    }

    @ExceptionHandler(MailException.class)
    public ResponseEntity<ApiError> handleMailFailure(MailException ex) {
        String raw = ex.getMostSpecificCause() != null ? ex.getMostSpecificCause().getMessage() : ex.getMessage();
        log.error("JavaMailSender delivery failed: {}", raw);
        String lower = raw != null ? raw.toLowerCase() : "";
        String safeMessage;
        if (lower.contains("authentication") || lower.contains("username and password") || lower.contains("535")) {
            safeMessage = "SMTP authentication failed. Verify SMTP_USERNAME and your 16-character Gmail App Password.";
        } else if (lower.contains("timed out") || lower.contains("connect") || lower.contains("connection refused")) {
            safeMessage = "SMTP connection failed or timed out (Render Free tier restricts outbound ports 25, 465, and 587; use port 2525 or a paid instance).";
        } else {
            safeMessage = "Unable to send email through SMTP server.";
        }
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(new ApiError(502, "MAIL_DELIVERY_FAILED", safeMessage, Instant.now()));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiError> handleIllegalState(IllegalStateException ex) {
        log.error("Mail configuration or composition error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(new ApiError(502, "MAIL_CONFIG_ERROR", ex.getMessage(), Instant.now()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
            .findFirst()
            .map(err -> err.getField() + ": " + err.getDefaultMessage())
            .orElse("Invalid request payload");
        return ResponseEntity.badRequest()
            .body(new ApiError(400, "VALIDATION_ERROR", message, Instant.now()));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex) {
        String message = ex.getConstraintViolations().stream()
            .findFirst()
            .map(v -> v.getMessage())
            .orElse("Invalid request parameter");
        return ResponseEntity.badRequest()
            .body(new ApiError(400, "VALIDATION_ERROR", message, Instant.now()));
    }
}
