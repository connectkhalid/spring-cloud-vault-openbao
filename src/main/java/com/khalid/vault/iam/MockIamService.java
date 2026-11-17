package com.khalid.vault.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalid.vault.admin.IntegrationIdentityService;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class MockIamService {
    private static final String HMAC = "HmacSHA256";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private final VaultServiceProperties properties;
    private final IntegrationIdentityService integrationIdentities;
    private final ObjectMapper objectMapper;
    private final byte[] signingKey;

    public MockIamService(VaultServiceProperties properties, ObjectMapper objectMapper,
                          IntegrationIdentityService integrationIdentities) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.integrationIdentities = integrationIdentities;
        this.signingKey = properties.getIam().getSigningSecret().getBytes(StandardCharsets.UTF_8);
        if (signingKey.length < 32) {
            throw new IllegalStateException("APP_TOKEN_SIGNING_SECRET must contain at least 32 bytes");
        }
        Set<String> namespaces = new HashSet<>();
        Set<String> openBaoTokens = new HashSet<>();
        Set<String> clientSecrets = new HashSet<>();
        properties.getIam().getApps().forEach((id, app) -> {
            if (!id.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
                throw new IllegalStateException("Invalid application id in IAM configuration: " + id);
            }
            if (app.getClientSecret().isBlank() || app.getOpenbaoToken().isBlank()) {
                throw new IllegalStateException("Client secret and OpenBao token must be configured for app " + id);
            }
            if (!namespaces.add(app.getNamespace())) {
                throw new IllegalStateException("Every configured app must have a distinct OpenBao namespace");
            }
            if (!openBaoTokens.add(app.getOpenbaoToken())) {
                throw new IllegalStateException("Every configured app must have a distinct OpenBao token");
            }
            if (!clientSecrets.add(app.getClientSecret())) {
                throw new IllegalStateException("Every configured app must have a distinct client secret");
            }
        });
        String operatorSecret = properties.getIam().getRotationOperatorSecret();
        if (!operatorSecret.isBlank()) {
            if (operatorSecret.length() < 32) {
                throw new IllegalStateException("ROTATION_OPERATOR_SECRET must contain at least 32 characters");
            }
            if (!clientSecrets.add(operatorSecret)) {
                throw new IllegalStateException("Rotation operator secret must differ from every app client secret");
            }
        }
        String adminUsername = properties.getIam().getAdminUsername();
        String adminPassword = properties.getIam().getAdminPassword();
        boolean hasAdminCredentials = !adminUsername.isBlank() || !adminPassword.isBlank();
        if (hasAdminCredentials && (adminUsername.isBlank() || adminPassword.isBlank()
                || properties.getOpenbao().getAdminToken().isBlank())) {
            throw new IllegalStateException("ADMIN_USERNAME, ADMIN_PASSWORD, and OPENBAO_ADMIN_TOKEN must be configured together");
        }
        if (!adminPassword.isBlank()) {
            if (adminPassword.length() < 32) {
                throw new IllegalStateException("ADMIN_PASSWORD must contain at least 32 characters");
            }
            if (!clientSecrets.add(adminPassword)) {
                throw new IllegalStateException("Administrator password must differ from app and rotation-operator secrets");
            }
        }
    }

    public String issueToken(String clientId, String clientSecret) {
        if ("rotation-operator".equals(clientId)) {
            String configured = properties.getIam().getRotationOperatorSecret();
            if (configured.isBlank() || clientSecret == null || !MessageDigest.isEqual(
                    configured.getBytes(StandardCharsets.UTF_8), clientSecret.getBytes(StandardCharsets.UTF_8))) {
                throw new ResponseStatusException(HttpStatusCodes.UNAUTHORIZED, "Invalid client credentials");
            }
            return issueSignedToken(clientId, "rotation-operator");
        }
        VaultServiceProperties.AppRegistration app = properties.getIam().getApps().get(clientId);
        if (app != null && clientSecret != null && MessageDigest.isEqual(
                app.getClientSecret().getBytes(StandardCharsets.UTF_8), clientSecret.getBytes(StandardCharsets.UTF_8))) {
            return issueSignedToken(clientId, null);
        }
        IntegrationIdentityService.IdentityRecord managed = integrationIdentities.find(clientId);
        if (managed == null || !managed.enabled() || !integrationIdentities.matchesSecret(managed, clientSecret)) {
            throw new ResponseStatusException(HttpStatusCodes.UNAUTHORIZED, "Invalid client credentials");
        }
        return issueSignedToken(clientId, null);
    }

    /** Authenticate the configured administrator and issue a role-bearing admin token. */
    public String issueAdminToken(String username, String password) {
        String expectedUser = properties.getIam().getAdminUsername();
        String expectedPassword = properties.getIam().getAdminPassword();
        if (expectedUser.isBlank() || expectedPassword.isBlank() || username == null || password == null
                || !MessageDigest.isEqual(expectedUser.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8))
                || !MessageDigest.isEqual(expectedPassword.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatusCodes.UNAUTHORIZED, "Invalid administrator credentials");
        }
        if (properties.getOpenbao().getAdminToken().isBlank()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "Admin login is disabled until OPENBAO_ADMIN_TOKEN is configured");
        }
        return issueSignedToken(username, "admin");
    }

    private String issueSignedToken(String subject, String role) {
        long now = Instant.now().getEpochSecond();
        long expires = now + properties.getIam().getTokenTtl().toSeconds();
        try {
            String header = encode(objectMapper.writeValueAsBytes(Map.of("alg", "HS256", "typ", "JWT")));
            Map<String, Object> claims = new java.util.HashMap<>();
            claims.put("sub", subject);
            claims.put("iat", now);
            claims.put("exp", expires);
            claims.put("iss", "mock-iam");
            if (role != null) claims.put("role", role);
            String payload = encode(objectMapper.writeValueAsBytes(claims));
            String content = header + "." + payload;
            return content + "." + ENCODER.encodeToString(sign(content));
        } catch (Exception exception) {
            throw new IllegalStateException("Could not issue application token", exception);
        }
    }

    public AppIdentity verifyToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new IllegalArgumentException("Malformed token");
            String content = parts[0] + "." + parts[1];
            byte[] expected = sign(content);
            if (!MessageDigest.isEqual(expected, DECODER.decode(parts[2]))) throw new IllegalArgumentException("Bad signature");
            Map<?, ?> header = objectMapper.readValue(DECODER.decode(parts[0]), Map.class);
            if (!"HS256".equals(header.get("alg")) || !"JWT".equals(header.get("typ"))) {
                throw new IllegalArgumentException("Unsupported token header");
            }
            Map<?, ?> claims = objectMapper.readValue(DECODER.decode(parts[1]), Map.class);
            if (!"mock-iam".equals(claims.get("iss")) || !(claims.get("exp") instanceof Number exp)
                    || exp.longValue() <= Instant.now().getEpochSecond()) {
                throw new IllegalArgumentException("Expired or invalid token");
            }
            String appId = String.valueOf(claims.get("sub"));
            if ("rotation-operator".equals(claims.get("role"))
                    && "rotation-operator".equals(appId)
                    && !properties.getIam().getRotationOperatorSecret().isBlank()) {
                return new AppIdentity(appId, null, true);
            }
            if ("admin".equals(claims.get("role"))
                    && appId.equals(properties.getIam().getAdminUsername())
                    && !properties.getIam().getAdminPassword().isBlank()
                    && !properties.getOpenbao().getAdminToken().isBlank()) {
                return new AppIdentity(appId, null, false, true);
            }
            VaultServiceProperties.AppRegistration registration = properties.getIam().getApps().get(appId);
            if (registration == null) {
                IntegrationIdentityService.IdentityRecord managed = integrationIdentities.find(appId);
                if (managed == null || !managed.enabled() || managed.openbaoToken().isBlank()) {
                    throw new IllegalArgumentException("Unknown or disabled integration identity");
                }
                registration = new VaultServiceProperties.AppRegistration();
                registration.setClientSecret(managed.credentialHash());
                registration.setNamespace(managed.namespace());
                registration.setOpenbaoToken(managed.openbaoToken());
            }
            return new AppIdentity(appId, registration);
        } catch (Exception exception) {
            throw new ResponseStatusException(HttpStatusCodes.UNAUTHORIZED, "Invalid or expired bearer token");
        }
    }

    public long tokenTtlSeconds() { return properties.getIam().getTokenTtl().toSeconds(); }

    private byte[] sign(String value) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(signingKey, HMAC));
        return mac.doFinal(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static String encode(byte[] value) { return ENCODER.encodeToString(value); }
}
