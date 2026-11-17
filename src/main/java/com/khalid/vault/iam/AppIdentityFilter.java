package com.khalid.vault.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.dto.common.ApiErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.khalid.vault.audit.AuditLoggerService;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Component
public class AppIdentityFilter extends OncePerRequestFilter {
    public static final String IDENTITY_ATTRIBUTE = AppIdentity.class.getName();
    private final MockIamService iam;
    private final AuditLoggerService auditLogger;
    private final ObjectMapper objectMapper;

    public AppIdentityFilter(MockIamService iam, AuditLoggerService auditLogger, ObjectMapper objectMapper) {
        this.iam = iam;
        this.auditLogger = auditLogger;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/api/auth/token") || path.equals("/api/auth/admin-token")
                || path.equals("/openapi.yaml")
                || path.equals("/actuator/health") || path.equals("/actuator/health/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            writeUnauthorized(request, response, "Bearer token required");
            return;
        }
        final AppIdentity identity;
        try {
            identity = iam.verifyToken(authorization.substring(7));
        } catch (org.springframework.web.server.ResponseStatusException exception) {
            writeUnauthorized(request, response, "Invalid or expired bearer token");
            return;
        }
        request.setAttribute("actorId", identity.appId());
        request.setAttribute(IDENTITY_ATTRIBUTE, identity);
        long startedAt = System.nanoTime();
        try {
            chain.doFilter(request, response);
        } finally {
            long durationMillis = (System.nanoTime() - startedAt) / 1_000_000L;
            auditLogger.authenticatedRequest(identity.appId(), request.getMethod(), request.getRequestURI(),
                    response.getStatus(), durationMillis);
        }
    }

    private void writeUnauthorized(HttpServletRequest request, HttpServletResponse response, String message)
            throws IOException {
        response.setStatus(HttpStatusCodes.UNAUTHORIZED_CODE);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(), new ApiErrorResponse(Instant.now(),
                HttpStatusCodes.UNAUTHORIZED_CODE, "UNAUTHORIZED", message, request.getRequestURI(), Map.of()));
        auditLogger.apiFailure("anonymous", request.getMethod(), request.getRequestURI(),
                HttpStatusCodes.UNAUTHORIZED_CODE, "UNAUTHORIZED", message,
                new org.springframework.web.server.ResponseStatusException(HttpStatusCodes.UNAUTHORIZED, message));
    }
}
