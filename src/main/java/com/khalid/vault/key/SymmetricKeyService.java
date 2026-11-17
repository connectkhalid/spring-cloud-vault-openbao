package com.khalid.vault.key;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.khalid.vault.audit.AuditLoggerService;
import com.khalid.vault.common.ApiException;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.dto.key.SymmetricKeyResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.openbao.OpenBaoClient;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/** Manages versioned, exportable HMAC keys for clients that sign locally. */
@Service
public class SymmetricKeyService {
    private static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern KEY_ID = Pattern.compile("v[1-9][0-9]{0,8}");
    private final OpenBaoClient openBao;
    private final ObjectMapper mapper;
    private final AuditLoggerService auditLogger;
    private final Duration defaultTtl;
    private final Duration renewalWindow;
    private final String kvMount;
    private final String transitMount;
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public SymmetricKeyService(OpenBaoClient openBao, ObjectMapper mapper, AuditLoggerService auditLogger,
                               VaultServiceProperties properties) {
        this.openBao = openBao;
        this.mapper = mapper;
        this.auditLogger = auditLogger;
        this.kvMount = properties.getOpenbao().getKvMount();
        this.transitMount = properties.getOpenbao().getTransitMount();
        this.defaultTtl = properties.getSymmetricKeys().getDefaultTtl();
        this.renewalWindow = properties.getSymmetricKeys().getRenewalWindow();
        if (defaultTtl == null || defaultTtl.isZero() || defaultTtl.isNegative()
                || renewalWindow == null || renewalWindow.isNegative() || renewalWindow.compareTo(defaultTtl) >= 0) {
            throw new IllegalStateException("Symmetric key renewal window must be non-negative and less than the positive key lifetime");
        }
    }

    /** Return or create an alias's active HMAC key, rotating it when it reaches the renewal window. */
    public SymmetricKeyResponse requestKey(AppIdentity identity, String alias, Boolean expirationEnabled) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        if (expirationEnabled == null) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "expirationEnabled is required");
        }
        return withLock(identity, alias, () -> {
            for (int attempt = 0; attempt < 8; attempt++) {
                JsonNode record = readRegistry(identity, alias);
                if (record == null) {
                    ObjectNode initial = mapper.createObjectNode();
                    initial.put("alias", alias);
                    initial.put("type", "hmac");
                    initial.put("expirationEnabled", expirationEnabled);
                    initial.putNull("activeKeyId");
                    initial.put("pendingKeyId", "v1");
                    ArrayNode keys = initial.putArray("keys");
                    keys.addObject().put("keyId", "v1")
                            .put("version", 1)
                            .put("transitName", transitName())
                            .put("state", "creating")
                            .put("createdAt", Instant.now().toString());
                    applyExpiry((ObjectNode) keys.get(0), expirationEnabled);
                    try {
                        writeRegistry(identity, alias, initial, 0);
                    } catch (ResponseStatusException exception) {
                        if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE) throw exception;
                    }
                    continue;
                }

                ObjectNode data = (ObjectNode) record.path("data");
                if (data.path("expirationEnabled").asBoolean(false) != expirationEnabled) {
                    throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                            "Expiration setting is fixed for an alias; use another alias to change it");
                }
                String pendingId = data.path("pendingKeyId").asText("");
                if (!pendingId.isBlank()) {
                    finishPending(identity, alias, pendingId);
                    continue;
                }

                String activeId = data.path("activeKeyId").asText("");
                ObjectNode active = findKey(data, activeId);
                if (active == null || !"active".equals(active.path("state").asText())) {
                    throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Symmetric key alias has no active key");
                }
                if (expirationEnabled && isWithinRenewalWindow(active)) {
                    stageReplacement(identity, alias, record, active);
                    continue;
                }
                return response(identity, alias, active);
            }
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                    "Symmetric key rotation is still being provisioned; retry the request");
        });
    }

    /** Return a historical HMAC key only while its configured verification lifetime remains valid. */
    public SymmetricKeyResponse getVersion(AppIdentity identity, String alias, String keyId) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateKeyId(keyId);
        JsonNode record = requireRegistry(identity, alias);
        ObjectNode data = (ObjectNode) record.path("data");
        ObjectNode key = findKey(data, keyId);
        if (key == null || "creating".equals(key.path("state").asText())) {
            throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Symmetric key version not found");
        }
        Instant expiresAt = instantOrNull(key.path("expiresAt"));
        if (expiresAt != null && !Instant.now().isBefore(expiresAt)) {
            throw new ApiException(HttpStatusCodes.GONE, "KEY_EXPIRED", "Symmetric key version has expired");
        }
        return response(identity, alias, key);
    }

    private void stageReplacement(AppIdentity identity, String alias, JsonNode record, ObjectNode active) {
        ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
        int next = 1;
        for (JsonNode entry : snapshot.path("keys")) next = Math.max(next, entry.path("version").asInt() + 1);
        String keyId = "v" + next;
        ObjectNode pending = snapshot.withArray("keys").addObject();
        pending.put("keyId", keyId);
        pending.put("version", next);
        pending.put("transitName", transitName());
        pending.put("state", "creating");
        pending.put("createdAt", Instant.now().toString());
        applyExpiry(pending, true);
        snapshot.put("pendingKeyId", keyId);
        try {
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());
            auditLogger.keyLifecycle(identity.appId(), alias, keyId, "stage_hmac_rotation", "success");
        } catch (ResponseStatusException exception) {
            if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE) throw exception;
        }
    }

    private void finishPending(AppIdentity identity, String alias, String keyId) {
        JsonNode current = requireRegistry(identity, alias);
        ObjectNode pending = findKey(current.path("data"), keyId);
        if (pending == null) return;
        if (!"creating".equals(pending.path("state").asText())) return;
        String transitName = pending.path("transitName").asText();
        String transitPath = transitKeyPath(transitName);
        JsonNode transit = openBao.getOrNull(identity, transitPath);
        if (transit == null) {
            openBao.post(identity, transitPath, Map.of("type", "hmac", "exportable", true));
        } else if (!"hmac".equals(transit.path("data").path("type").asText())
                || !transit.path("data").path("exportable").asBoolean(false)) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                    "Pending Transit key is not an exportable HMAC key");
        }
        // Confirm export permission and key existence before publishing this version as active.
        export(identity, transitName);

        for (int attempt = 0; attempt < 5; attempt++) {
            JsonNode latest = requireRegistry(identity, alias);
            ObjectNode latestData = (ObjectNode) latest.path("data");
            if (!keyId.equals(latestData.path("pendingKeyId").asText())) return;
            ObjectNode snapshot = (ObjectNode) latestData.deepCopy();
            String previousId = snapshot.path("activeKeyId").asText("");
            ObjectNode previous = findKey(snapshot, previousId);
            if (previous != null) {
                Instant oldExpiry = instantOrNull(previous.path("expiresAt"));
                previous.put("state", oldExpiry != null && !Instant.now().isBefore(oldExpiry) ? "expired" : "verify-only");
            }
            ObjectNode replacement = findKey(snapshot, keyId);
            if (replacement == null) throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Pending HMAC key was removed");
            replacement.put("state", "active");
            snapshot.put("activeKeyId", keyId);
            snapshot.putNull("pendingKeyId");
            try {
                writeRegistry(identity, alias, snapshot, latest.path("version").asLong());
                auditLogger.keyLifecycle(identity.appId(), alias, keyId,
                        previousId.isBlank() ? "create_hmac_key" : "activate_hmac_key", "success");
                return;
            } catch (ResponseStatusException exception) {
                if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE || attempt == 4) throw exception;
            }
        }
    }

    private SymmetricKeyResponse response(AppIdentity identity, String alias, ObjectNode metadata) {
        String transitName = metadata.path("transitName").asText();
        String keyId = metadata.path("keyId").asText();
        Instant expiry = instantOrNull(metadata.path("expiresAt"));
        Instant refreshAt = instantOrNull(metadata.path("refreshAt"));
        return new SymmetricKeyResponse(alias, "HMAC-SHA-256", keyId,
                export(identity, transitName), metadata.has("expiresAt") && !metadata.path("expiresAt").isNull(),
                refreshAt, expiry);
    }

    private String export(AppIdentity identity, String transitName) {
        JsonNode result = openBao.getWithQuery(identity,
                "/v1/" + transitMount + "/export/hmac-key/" + transitName + "/1", "format", "raw");
        JsonNode keys = result.path("data").path("keys");
        JsonNode value = keys.path("1");
        if (value.isMissingNode() && keys.isObject() && keys.size() > 0) value = keys.elements().next();
        if (value.isMissingNode() || value.isNull() || value.asText().isBlank()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_GATEWAY, "OpenBao did not return HMAC key material");
        }
        return value.asText();
    }

    private boolean isWithinRenewalWindow(ObjectNode active) {
        Instant refreshAt = instantOrNull(active.path("refreshAt"));
        return refreshAt != null && !Instant.now().isBefore(refreshAt);
    }

    private void applyExpiry(ObjectNode key, boolean expires) {
        if (!expires) {
            key.putNull("refreshAt");
            key.putNull("expiresAt");
            return;
        }
        Instant expiresAt = Instant.now().plus(defaultTtl);
        key.put("expiresAt", expiresAt.toString());
        key.put("refreshAt", expiresAt.minus(renewalWindow).toString());
    }

    private JsonNode readRegistry(AppIdentity identity, String alias) {
        JsonNode response = openBao.getOrNull(identity, registryPath(alias));
        if (response == null) return null;
        ObjectNode envelope = mapper.createObjectNode();
        envelope.set("data", response.path("data").path("data").deepCopy());
        envelope.put("version", response.path("data").path("metadata").path("version").asLong());
        return envelope;
    }

    private JsonNode requireRegistry(AppIdentity identity, String alias) {
        JsonNode record = readRegistry(identity, alias);
        if (record == null) throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Symmetric key alias not found");
        return record;
    }

    private void writeRegistry(AppIdentity identity, String alias, JsonNode data, long expectedVersion) {
        openBao.putKvV2Cas(identity, registryPath(alias), data, expectedVersion);
    }

    private String registryPath(String alias) {
        return "/v1/" + kvMount + "/data/_internal/symmetric-key-registry/" + alias;
    }

    private String transitKeyPath(String transitName) { return "/v1/" + transitMount + "/keys/" + transitName; }

    private String transitName() { return "hmac-" + UUID.randomUUID().toString().replace("-", ""); }

    private ObjectNode findKey(JsonNode data, String keyId) {
        if (keyId == null || keyId.isBlank()) return null;
        for (JsonNode node : data.path("keys")) {
            if (keyId.equals(node.path("keyId").asText())) return (ObjectNode) node;
        }
        return null;
    }

    private Instant instantOrNull(JsonNode value) {
        if (value == null || value.isMissingNode() || value.isNull() || value.asText().isBlank()) return null;
        return Instant.parse(value.asText());
    }

    private void validateAlias(String alias) {
        if (alias == null || !ALIAS.matcher(alias).matches()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Invalid symmetric key alias");
        }
    }

    private void validateKeyId(String keyId) {
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Invalid symmetric key ID");
        }
    }

    private void ensureAppIdentity(AppIdentity identity) {
        if (identity == null || identity.registration() == null || identity.adminUser() || identity.rotationOperator()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "An app-scoped identity is required for symmetric key operations");
        }
    }

    private <T> T withLock(AppIdentity identity, String alias, Operation<T> operation) {
        ReentrantLock lock = locks.computeIfAbsent(identity.appId() + ":" + alias, ignored -> new ReentrantLock());
        lock.lock();
        try { return operation.run(); }
        finally { lock.unlock(); }
    }

    @FunctionalInterface
    private interface Operation<T> { T run(); }
}
