package com.mailotp.service;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class KeepAliveScheduler {

    private static final Logger log = LoggerFactory.getLogger(KeepAliveScheduler.class);

    private final boolean enabled;
    private final URI targetUri;
    private final HttpClient httpClient;

    public KeepAliveScheduler(
        @Value("${otp.keep-alive.enabled:true}") boolean enabled,
        @Value("${otp.keep-alive.url:}") String configuredUrl
    ) {
        this.enabled = enabled;
        this.targetUri = resolveSafePublicHealthUri(configuredUrl);
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    @Scheduled(
        initialDelayString = "${otp.keep-alive.interval-ms:600000}",
        fixedDelayString = "${otp.keep-alive.interval-ms:600000}"
    )
    public void pingHealthEndpoint() {
        if (!enabled || targetUri == null) {
            return;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            log.debug("Keep-alive ping to {} returned HTTP {}", targetUri, response.statusCode());
        } catch (Exception ex) {
            log.debug("Keep-alive ping failed: {}", ex.getMessage());
        }
    }

    private URI resolveSafePublicHealthUri(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return null;
        }
        try {
            String trimmed = rawUrl.trim().replaceAll("/+$", "");
            String fullUrl = trimmed.endsWith("/api/health") ? trimmed : trimmed + "/api/health";
            URI uri = URI.create(fullUrl);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return null;
            }
            if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
                return null;
            }
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (addr.isAnyLocalAddress()
                    || addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress()
                    || addr.isMulticastAddress()) {
                    log.warn("Ignoring non-public keep-alive host: {}", host);
                    return null;
                }
            }
            return uri;
        } catch (Exception ex) {
            log.warn("Invalid keep-alive URL configured; scheduler disabled.");
            return null;
        }
    }
}
