package com.khalid.vault.admin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalid.vault.common.ApiException;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.dto.admin.IntegrationIdentityRequest;
import com.khalid.vault.dto.admin.IntegrationIdentityResponse;
import com.khalid.vault.openbao.OpenBaoClient;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** OpenBao-backed registry for separately authenticated integration service identities. */
@Service
public class IntegrationIdentityService {
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,58}");
    private static final Pattern POLICY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final String REGISTRY_PATH = "_service/integration-identities/";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OpenBaoClient openBao;
    private final ObjectMapper mapper;
    private final VaultServiceProperties properties;

    public IntegrationIdentityService(OpenBaoClient openBao, ObjectMapper mapper, VaultServiceProperties properties) {
        this.openBao = openBao;
        this.mapper = mapper;
        this.properties = properties;
    }

    public IntegrationIdentityResponse create(String id, IntegrationIdentityRequest request) {
        validateId(id);
        validateRequest(request);
        if (properties.getIam().getApps().containsKey(id)) {
            throw new ApiException(HttpStatusCodes.CONFLICT, "IDENTITY_EXISTS", "Integration identity id is already configured");
        }
        if (openBao.adminGetOrNull(registryDataPath(id), registryNamespace()) != null) {
            throw new ApiException(HttpStatusCodes.CONFLICT, "IDENTITY_EXISTS", "Integration identity already exists");
        }
        String role = roleName(id);
        configureRole(request.namespace(), role, request.policies());
        String clientSecret = randomSecret();
        String token = mintToken(request.namespace(), role);
        IdentityRecord record = new IdentityRecord(id, request.namespace(), request.policies(), true,
                credentialHash(clientSecret), token, role);
        try {
            save(record);
        } catch (RuntimeException exception) {
            try { revoke(request.namespace(), token); } catch (RuntimeException ignored) { }
            try { openBao.adminDelete("/v1/auth/token/roles/" + role, request.namespace()); } catch (RuntimeException ignored) { }
            throw exception;
        }
        return response(record, clientSecret);
    }

    public IntegrationIdentityResponse read(String id) {
        return response(requireRecord(id), null);
    }

    public List<IntegrationIdentityResponse> list() {
        JsonNode entries = openBao.adminGet(registryMetadataPath() + "?list=true", registryNamespace()).path("data").path("keys");
        List<IntegrationIdentityResponse> result = new ArrayList<>();
        if (entries.isArray()) {
            for (JsonNode entry : entries) {
                String id = entry.asText().replace("/", "");
                IdentityRecord record = find(id);
                if (record != null) result.add(response(record, null));
            }
        }
        return result;
    }

    public void renewTokens() {
        JsonNode entries = openBao.adminGet(registryMetadataPath() + "?list=true", registryNamespace())
                .path("data").path("keys");
        if (!entries.isArray()) return;
        for (JsonNode entry : entries) {
            String id = entry.asText().replace("/", "");
            IdentityRecord record = find(id);
            if (record == null || !record.enabled() || record.openbaoToken().isBlank()) continue;
            VaultServiceProperties.AppRegistration registration = new VaultServiceProperties.AppRegistration();
            registration.setClientSecret(record.credentialHash());
            registration.setNamespace(record.namespace());
            registration.setOpenbaoToken(record.openbaoToken());
            try {
                openBao.renewToken(new com.khalid.vault.iam.AppIdentity(record.id(), registration));
                persistRenewedToken(record.id(), registration.getOpenbaoToken());
            } catch (Exception exception) {
                // Renewal failures are isolated per identity; its next API request will surface token expiry.
            }
        }
    }

    public IntegrationIdentityResponse update(String id, IntegrationIdentityRequest request) {
        validateId(id);
        validateRequest(request);
        IdentityRecord current = requireRecord(id);
        if (!current.namespace().equals(request.namespace())) {
            throw new ApiException(HttpStatusCodes.BAD_REQUEST, "IDENTITY_NAMESPACE_IMMUTABLE",
                    "An integration identity cannot be moved to another namespace");
        }
        configureRole(current.namespace(), current.role(), request.policies());
        String replacementToken = current.enabled() ? mintToken(current.namespace(), current.role()) : "";
        IdentityRecord updated = new IdentityRecord(id, current.namespace(), request.policies(), current.enabled(),
                current.credentialHash(), replacementToken, current.role());
        save(updated);
        if (current.enabled()) revoke(current.namespace(), current.openbaoToken());
        return response(updated, null);
    }

    public IntegrationIdentityResponse disable(String id) {
        IdentityRecord current = requireRecord(id);
        IdentityRecord disabled = new IdentityRecord(current.id(), current.namespace(), current.policies(), false,
                current.credentialHash(), "", current.role());
        save(disabled);
        revoke(current.namespace(), current.openbaoToken());
        return response(disabled, null);
    }

    public IntegrationIdentityResponse enable(String id) {
        IdentityRecord current = requireRecord(id);
        if (current.enabled()) return response(current, null);
        String token = mintToken(current.namespace(), current.role());
        IdentityRecord enabled = new IdentityRecord(current.id(), current.namespace(), current.policies(), true,
                current.credentialHash(), token, current.role());
        save(enabled);
        return response(enabled, null);
    }

    public IntegrationIdentityResponse rotateCredential(String id) {
        IdentityRecord current = requireRecord(id);
        String secret = randomSecret();
        IdentityRecord updated = new IdentityRecord(current.id(), current.namespace(), current.policies(), current.enabled(),
                credentialHash(secret), current.openbaoToken(), current.role());
        save(updated);
        return response(updated, secret);
    }

    public void delete(String id) {
        IdentityRecord current = requireRecord(id);
        if (!current.openbaoToken().isBlank()) revoke(current.namespace(), current.openbaoToken());
        openBao.adminDelete(registryMetadataPath(id), registryNamespace());
        openBao.adminDelete("/v1/auth/token/roles/" + current.role(), current.namespace());
    }

    /** Resolve an identity during credential login or bearer-token verification. */
    public IdentityRecord find(String id) {
        if (id == null || !ID.matcher(id).matches()) return null;
        JsonNode response = openBao.adminGetOrNull(registryDataPath(id), registryNamespace());
        return response == null ? null : decode(response.path("data").path("data"));
    }

    public boolean matchesSecret(IdentityRecord identity, String candidate) {
        return candidate != null && MessageDigest.isEqual(identity.credentialHash().getBytes(StandardCharsets.US_ASCII),
                credentialHash(candidate).getBytes(StandardCharsets.US_ASCII));
    }

    public void persistRenewedToken(String id, String token) {
        IdentityRecord current = find(id);
        if (current != null && current.enabled()) {
            save(new IdentityRecord(current.id(), current.namespace(), current.policies(), true,
                    current.credentialHash(), token, current.role()));
        }
    }

    private void validateRequest(IntegrationIdentityRequest request) {
        if (request == null || request.namespace() == null || !request.namespace().matches(
                "[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63})*")) {
            throw new ApiException(HttpStatusCodes.BAD_REQUEST, "INVALID_NAMESPACE", "Invalid integration namespace");
        }
        if (request.policies() == null || request.policies().isEmpty()
                || request.policies().stream().anyMatch(policy -> !POLICY.matcher(policy).matches()
                || "root".equalsIgnoreCase(policy))) {
            throw new ApiException(HttpStatusCodes.BAD_REQUEST, "INVALID_IDENTITY_POLICIES",
                    "At least one valid non-root policy is required");
        }
        for (String policy : request.policies()) {
            if (!"default".equals(policy)) openBao.adminGet("/v1/sys/policies/acl/" + policy, request.namespace());
        }
    }

    private IdentityRecord requireRecord(String id) {
        validateId(id);
        IdentityRecord record = find(id);
        if (record == null) throw new ApiException(HttpStatusCodes.NOT_FOUND, "IDENTITY_NOT_FOUND", "Integration identity not found");
        return record;
    }

    private void configureRole(String namespace, String role, Set<String> policies) {
        openBao.adminPost("/v1/auth/token/roles/" + role, Map.of(
                "allowed_policies", policies,
                "period", "24h",
                "orphan", true,
                "token_no_default_policy", true), namespace);
    }

    private String mintToken(String namespace, String role) {
        JsonNode result = openBao.adminPost("/v1/auth/token/create/" + role, Map.of(), namespace);
        String token = result.path("auth").path("client_token").asText();
        if (token.isBlank()) throw new ApiException(HttpStatusCodes.BAD_GATEWAY, "TOKEN_ISSUE_FAILED",
                "OpenBao did not return an integration token");
        return token;
    }

    private void revoke(String namespace, String token) {
        if (token != null && !token.isBlank()) {
            openBao.adminPost("/v1/auth/token/revoke", Map.of("token", token), namespace);
        }
    }

    private void save(IdentityRecord record) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", record.id());
        data.put("namespace", record.namespace());
        data.put("policies", record.policies());
        data.put("enabled", record.enabled());
        data.put("credentialHash", record.credentialHash());
        data.put("openbaoToken", record.openbaoToken());
        data.put("role", record.role());
        openBao.adminPost(registryDataPath(record.id()), Map.of("data", data), registryNamespace());
    }

    private IdentityRecord decode(JsonNode data) {
        return new IdentityRecord(data.path("id").asText(), data.path("namespace").asText(),
                mapper.convertValue(data.path("policies"), new TypeReference<Set<String>>() { }),
                data.path("enabled").asBoolean(), data.path("credentialHash").asText(),
                data.path("openbaoToken").asText(), data.path("role").asText());
    }

    private IntegrationIdentityResponse response(IdentityRecord record, String secret) {
        return new IntegrationIdentityResponse(record.id(), record.namespace(), record.policies(), record.enabled(), secret);
    }

    private String credentialHash(String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(properties.getIam().getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Could not verify integration credential", exception);
        }
    }

    private String randomSecret() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String roleName(String id) { return "svc-" + id; }
    private String registryNamespace() { return properties.getIam().getIdentityRegistryNamespace(); }
    private String registryMetadataPath() { return "/v1/" + properties.getOpenbao().getKvMount() + "/metadata/" + REGISTRY_PATH; }
    private String registryMetadataPath(String id) { return registryMetadataPath() + id; }
    private String registryDataPath(String id) { return "/v1/" + properties.getOpenbao().getKvMount() + "/data/" + REGISTRY_PATH + id; }

    private void validateId(String id) {
        if (id == null || !ID.matcher(id).matches()) {
            throw new ApiException(HttpStatusCodes.BAD_REQUEST, "INVALID_IDENTITY_ID", "Invalid integration identity id");
        }
    }

    public record IdentityRecord(String id, String namespace, Set<String> policies, boolean enabled,
                                 String credentialHash, String openbaoToken, String role) { }
}
