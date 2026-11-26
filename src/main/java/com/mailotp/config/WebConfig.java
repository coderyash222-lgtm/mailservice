package com.mailotp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class WebConfig {

    @Bean
    public CorsFilter corsFilter(
        @Value("${otp.cors.allowed-origins:*}") String origins,
        @Value("${otp.api-key:}") String configuredApiKey
    ) {
        CorsConfiguration config = new CorsConfiguration();
        boolean apiKeyActive = configuredApiKey != null && !configuredApiKey.isBlank();

        Arrays.stream(origins.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .filter(s -> !apiKeyActive || !"*".equals(s))
            .forEach(config::addAllowedOriginPattern);

        config.setAllowCredentials(false);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("Content-Type", "X-API-Key", "Authorization"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public OncePerRequestFilter apiKeyFilter(@Value("${otp.api-key:}") String configuredApiKey) {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain filterChain
            ) throws ServletException, IOException {
                String path = request.getRequestURI();
                if (!path.startsWith("/api/v1/")) {
                    filterChain.doFilter(request, response);
                    return;
                }

                if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
                    filterChain.doFilter(request, response);
                    return;
                }

                if (configuredApiKey == null || configuredApiKey.isBlank()) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String incomingKey = request.getHeader("X-API-Key");
                if (incomingKey == null || !constantTimeEquals(configuredApiKey, incomingKey)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401,\"error\":\"UNAUTHORIZED\",\"message\":\"Missing or invalid X-API-Key header.\"}");
                    return;
                }

                filterChain.doFilter(request, response);
            }
        };
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        byte[] a = expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = actual.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }
}
