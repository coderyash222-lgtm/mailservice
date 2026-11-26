package com.mailotp.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

@Service
public class MailSenderService {

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String defaultAppName;

    public MailSenderService(
        JavaMailSender mailSender,
        @Value("${otp.mail.from:${spring.mail.username:no-reply@example.com}}") String fromAddress,
        @Value("${otp.app-name:AuthVerify}") String defaultAppName
    ) {
        this.mailSender = mailSender;
        this.fromAddress = sanitizeHeader(fromAddress);
        this.defaultAppName = defaultAppName;
    }

    public void sendOtpEmail(String recipientEmail, String otpCode, int expiresInSeconds, String requestedAppName) {
        String appName = (requestedAppName != null && !requestedAppName.isBlank())
            ? sanitizeHeader(requestedAppName.trim())
            : sanitizeHeader(defaultAppName);

        int expiryMinutes = Math.max(1, expiresInSeconds / 60);
        String subject = appName + " verification code: " + otpCode;
        String plainText = buildPlainText(appName, otpCode, expiryMinutes);
        String htmlBody = buildHtmlTemplate(appName, otpCode, expiryMinutes);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromAddress);
            helper.setTo(sanitizeHeader(recipientEmail));
            helper.setSubject(subject);
            helper.setText(plainText, htmlBody);
            mailSender.send(message);
        } catch (MessagingException ex) {
            throw new IllegalStateException("Failed to compose OTP email via JavaMailSender", ex);
        }
    }

    private String sanitizeHeader(String value) {
        return value.replaceAll("[\\r\\n]+", " ").trim();
    }

    private String buildPlainText(String appName, String otpCode, int expiryMinutes) {
        return appName + " Email Verification\n\n"
            + "Your one-time verification code is: " + otpCode + "\n\n"
            + "This code expires in " + expiryMinutes + " minutes.\n"
            + "If you did not request this code, you can safely ignore this email.\n";
    }

    private String buildHtmlTemplate(String appName, String otpCode, int expiryMinutes) {
        String safeAppName = HtmlUtils.htmlEscape(appName);
        String safeCode = HtmlUtils.htmlEscape(otpCode);

        return """
            <!DOCTYPE html>
            <html lang="en">
            <body style="margin:0;padding:32px 16px;background-color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#0f172a;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;">
                <tr>
                  <td style="padding:32px;">
                    <p style="margin:0 0 8px 0;font-size:13px;font-weight:600;color:#475569;">%s</p>
                    <h1 style="margin:0 0 16px 0;font-size:20px;font-weight:700;color:#0f172a;">Verify your email address</h1>
                    <p style="margin:0 0 24px 0;font-size:14px;line-height:1.6;color:#334155;">
                      Use the single-use verification code below to complete your sign-in. This code expires in %d minutes.
                    </p>
                    <div style="margin:0 0 24px 0;padding:18px 20px;background-color:#f1f5f9;border:1px solid #e2e8f0;border-radius:8px;text-align:center;">
                      <span style="font-family:'SFMono-Regular',Consolas,monospace;font-size:32px;font-weight:700;letter-spacing:8px;color:#0f172a;">%s</span>
                    </div>
                    <p style="margin:0;font-size:12px;line-height:1.5;color:#64748b;">
                      If you did not request this verification email, no further action is needed.
                    </p>
                  </td>
                </tr>
              </table>
            </body>
            </html>
            """.formatted(safeAppName, expiryMinutes, safeCode);
    }
}
