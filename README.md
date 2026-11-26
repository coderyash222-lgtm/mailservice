# Mail OTP Service (Spring Boot + JavaMailSender)

Monolithic, stateless-friendly email OTP authentication microservice built with Spring Boot 3.4, Java 21, and `JavaMailSender`.

## Exposed Endpoints

- `POST /api/v1/otp/send` — Generates a 6-digit `SecureRandom` OTP, stores a salted SHA-256 hash with TTL, and dispatches an HTML verification email via `JavaMailSender`.
- `POST /api/v1/otp/verify` — Performs constant-time verification (`MessageDigest.isEqual`) with single-use invalidation and 5-attempt lockout.
- `GET /api/v1/otp/status?email=...` — Returns active TTL, resend cooldown, and remaining verification attempts.
- `GET /api/health` — Readiness probe for Render, Railway, Fly.io, and Docker.

## Keeping Render Free Tier Awake

Render's free tier spins down containers after 15 minutes with no inbound HTTP traffic. This project includes two keep-alive mechanisms:

1. **Built-in `KeepAliveScheduler`**: Automatically pings `${RENDER_EXTERNAL_URL}/api/health` every 10 minutes (`KEEP_ALIVE_INTERVAL_MS=600000`) when deployed on Render.
2. **External Pinger (Recommended)**: Render may still require traffic originating outside its container network. Enable the included `.github/workflows/keep-alive.yml` workflow by setting a GitHub repository variable `OTP_SERVICE_URL` (e.g., `https://mail-otp-service.onrender.com`), or point a free monitor such as UptimeRobot or cron-job.org at `GET /api/health` every 10 minutes.

## Quick Start (Docker)

```bash
docker compose up --build
```

Open `http://localhost:8025` for the local Mailpit inbox, or set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, and `SMTP_PASSWORD` for Gmail/Brevo/Resend SMTP.

## Quick Start (Maven)

```bash
export SMTP_USERNAME="coderyash2222@gmail.com"
export SMTP_PASSWORD="your-16-char-app-password"
mvn spring-boot:run
```
