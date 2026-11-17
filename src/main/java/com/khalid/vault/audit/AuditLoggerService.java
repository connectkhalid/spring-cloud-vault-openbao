package com.khalid.vault.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;

/** Writes concise audit events to the application terminal log. Never pass secret values to this service. */
@Service
public class AuditLoggerService {
    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    public void authenticatedRequest(String appId, String method, String path, int status, long durationMillis) {
        auditLog.info("event=http_request actor={} method={} path={} status={} at={} duration_ms={}",
                safe(appId), safe(method), safe(path), status, Instant.now(), durationMillis);
    }

    public void authenticationSucceeded(String appId) {
        auditLog.info("event=authentication_success actor={} method=POST path=/api/auth/token status=200 at={}",
                safe(appId), Instant.now());
    }

    public void apiFailure(String actor, String method, String path, int status, String code,
                           String message, Exception exception) {
        auditLog.warn("event=api_failure actor={} method={} path={} status={} code={} message={} exception={} at={}",
                safe(actor), safe(method), safe(path), status, safe(code), safe(message),
                exception.getClass().getSimpleName(), Instant.now());
    }

    public void adminAction(String actor, String action, String resource, String result) {
        auditLog.info("event=admin_action actor={} action={} resource={} result={} at={}",
                safe(actor), safe(action), safe(resource), safe(result), Instant.now());
    }

    public void keyLifecycle(String appId, String alias, String keyId, String action, String result) {
        auditLog.info("event=key_lifecycle actor={} alias={} key_id={} action={} result={} at={}",
                safe(appId), safe(alias), safe(keyId), safe(action), safe(result), Instant.now());
    }

    public void keyLifecycle(String actor, String appId, String alias, String keyId, String action, String result) {
        auditLog.info("event=key_lifecycle actor={} target_app={} alias={} key_id={} action={} result={} at={}",
                safe(actor), safe(appId), safe(alias), safe(keyId), safe(action), safe(result), Instant.now());
    }

    private static String safe(String value) {
        if (value == null) return "unknown";
        // Prevent control characters and whitespace from forging additional terminal log lines/fields.
        return value.replaceAll("[\\r\\n\\t ]", "_");
    }
}
