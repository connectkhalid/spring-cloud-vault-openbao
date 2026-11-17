package com.khalid.vault.iam;

import com.khalid.vault.audit.AuditLoggerService;
import com.khalid.vault.dto.auth.AdminLoginRequest;
import com.khalid.vault.dto.auth.TokenRequest;
import com.khalid.vault.dto.auth.TokenResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final MockIamService iam;
    private final AuditLoggerService auditLogger;
    public AuthController(MockIamService iam, AuditLoggerService auditLogger) {
        this.iam = iam;
        this.auditLogger = auditLogger;
    }

    @PostMapping("/token")
    public TokenResponse issue(@Valid @RequestBody TokenRequest request) {
        String token = iam.issueToken(request.clientId(), request.clientSecret());
        auditLogger.authenticationSucceeded(request.clientId());
        return new TokenResponse(token, "Bearer", iam.tokenTtlSeconds());
    }

    @PostMapping("/admin-token")
    public TokenResponse issueAdmin(@Valid @RequestBody AdminLoginRequest request) {
        String token = iam.issueAdminToken(request.username(), request.password());
        auditLogger.authenticationSucceeded(request.username());
        return new TokenResponse(token, "Bearer", iam.tokenTtlSeconds());
    }
}
