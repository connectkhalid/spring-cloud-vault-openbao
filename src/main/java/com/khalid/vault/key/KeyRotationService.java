package com.khalid.vault.key;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.khalid.vault.audit.AuditLoggerService;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.dto.key.EmergencyRotationRequest;
import com.khalid.vault.dto.key.KeyResponse;
import com.khalid.vault.dto.key.PolicyResponse;
import com.khalid.vault.dto.key.PublicKeyEntry;
import com.khalid.vault.dto.key.RotationRunResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.openbao.OpenBaoClient;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class KeyRotationService {
    private static final Set<String> TRANSIT_TYPES = Set.of("rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256",
            "ecdsa-p384", "ecdsa-p521", "ed25519", "mldsa-44", "mldsa-65", "mldsa-87");
    private static final java.util.regex.Pattern ALIAS = java.util.regex.Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final java.util.regex.Pattern KEY_ID = java.util.regex.Pattern.compile("v[1-9][0-9]{0,8}");
    private final OpenBaoClient openBao;
    private final ObjectMapper mapper;
    private final AuditLoggerService auditLogger;
    private final VaultServiceProperties properties;
    private final Set<String> supportedTypes;
    private final String kvMount;
    private final String transitMount;
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public KeyRotationService(OpenBaoClient openBao, ObjectMapper mapper, AuditLoggerService auditLogger,
                              VaultServiceProperties properties) {
        this.openBao = openBao;
        this.mapper = mapper;
        this.auditLogger = auditLogger;
        this.properties = properties;
        this.kvMount = properties.getOpenbao().getKvMount();
        this.transitMount = properties.getOpenbao().getTransitMount();
        this.supportedTypes = Set.copyOf(properties.getOpenbao().getSupportedKeyTypes());
    }

    public Set<String> supportedTypes() { return supportedTypes; }

    /** Validate the app and algorithm, then return or initialize the active key pair. */
    public KeyResponse getOrCreateActive(AppIdentity identity, String alias, String type) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateType(type);
        return withLock(identity, alias, () -> {
            JsonNode record = readRegistry(identity, alias);
            if (record == null) record = initializeRegistry(identity, alias, type);
            ensureType(record, type);
            ObjectNode active = findKey(record, record.path("data").path("activeKeyId").asText());
            if (active == null || !"active".equals(active.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Key alias has no active key");
            }
            KeyResponse response = pair(identity, alias, active, true);
            auditLogger.keyLifecycle(identity.appId(), alias, active.path("keyId").asText(),
                    "private_key_delivered", "success");
            return response;
        });
    }

    /** Export the active pair only for the app owning the namespace and audit delivery. */
    public KeyResponse getActivePair(AppIdentity identity, String alias) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        JsonNode record = requireRegistry(identity, alias);
        ObjectNode active = requireKey(record, record.path("data").path("activeKeyId").asText());
        if (!"active".equals(active.path("state").asText())) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Key alias has no active key");
        }
        KeyResponse response = pair(identity, alias, active, true);
        auditLogger.keyLifecycle(identity.appId(), alias, active.path("keyId").asText(),
                "private_key_delivered", "success");
        return response;
    }

    public PolicyResponse getPolicy(AppIdentity identity, String alias) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        JsonNode record = requireRegistry(identity, alias);
        JsonNode policy = record.path("data").path("rotationPolicy");
        return new PolicyResponse(alias, policy.path("enabled").asBoolean(false),
                policy.path("intervalSeconds").asLong(0), policy.path("lastRotatedAt").asText(null));
    }

    /** Validate and persist the per-alias interval policy using KV compare-and-set. */
    public PolicyResponse updatePolicy(AppIdentity identity, String alias, boolean enabled, long intervalSeconds) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        if (enabled && intervalSeconds <= 0) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "An enabled policy requires a positive intervalSeconds");
        }
        return withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
            ObjectNode policy = snapshot.with("rotationPolicy");
            policy.put("enabled", enabled);
            policy.put("intervalSeconds", intervalSeconds);
            if (policy.path("lastRotatedAt").isMissingNode()) {
                policy.put("lastRotatedAt", requireKey(snapshot, snapshot.path("activeKeyId").asText())
                        .path("createdAt").asText(Instant.now().toString()));
            }
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());
            auditLogger.keyLifecycle(identity.appId(), alias, snapshot.path("activeKeyId").asText(),
                    "update_rotation_policy", "success");
            return getPolicy(identity, alias);
        });
    }

    /** Check policy age and rotate once due; KV compare-and-set coordinates service replicas. */
    public RotationRunResponse runPolicy(AppIdentity identity, String alias) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        return withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            JsonNode policy = record.path("data").path("rotationPolicy");
            if (!policy.path("enabled").asBoolean(false) || policy.path("intervalSeconds").asLong() <= 0) {
                return new RotationRunResponse(alias, false, false,
                        record.path("data").path("activeKeyId").asText(), "disabled");
            }
            Instant last = Instant.parse(policy.path("lastRotatedAt").asText(
                    requireKey(record, record.path("data").path("activeKeyId").asText()).path("createdAt").asText()));
            if (Instant.now().isBefore(last.plus(Duration.ofSeconds(policy.path("intervalSeconds").asLong())))) {
                return new RotationRunResponse(alias, true, false,
                        record.path("data").path("activeKeyId").asText(), "not-due");
            }
            String type = record.path("data").path("type").asText();
            String previousActiveId = record.path("data").path("activeKeyId").asText();
            try {
                String keyId = ensurePendingThenActivate(identity, alias, type, false);
                return new RotationRunResponse(alias, true, true, keyId, "rotated");
            } catch (ResponseStatusException exception) {
                if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE) throw exception;
                JsonNode latest = requireRegistry(identity, alias);
                String activeId = latest.path("data").path("activeKeyId").asText();
                if (!previousActiveId.equals(activeId)) {
                    return new RotationRunResponse(alias, true, true, activeId, "already-rotated");
                }
                throw exception;
            }
        });
    }

    /** Force a new active key and revoke the key active when the emergency request began. */
    public RotationRunResponse emergencyRotate(AppIdentity caller, String alias, EmergencyRotationRequest request) {
        AppIdentity identity = resolveEmergencyTarget(caller, request);
        validateAlias(alias);
        String actor = caller.appId();
        return withLock(identity, alias, () -> {
            String initiallyCompromisedKeyId = requireRegistry(identity, alias)
                    .path("data").path("activeKeyId").asText();
            for (int attempt = 0; attempt < 3; attempt++) {
                JsonNode record = requireRegistry(identity, alias);
                try {
                    String keyId = ensurePendingThenActivate(identity, alias,
                            record.path("data").path("type").asText(), true);
                    revokeCompromisedKey(identity, alias, initiallyCompromisedKeyId);
                    auditLogger.keyLifecycle(actor, identity.appId(), alias, keyId, "emergency_rotation", "success");
                    return new RotationRunResponse(alias, true, true, keyId, "rotated");
                } catch (ResponseStatusException exception) {
                    if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE || attempt == 2) throw exception;
                    JsonNode latest = requireRegistry(identity, alias);
                    ObjectNode compromised = findKey(latest, initiallyCompromisedKeyId);
                    if (compromised != null && "revoked".equals(compromised.path("state").asText())) {
                        String activeId = latest.path("data").path("activeKeyId").asText();
                        auditLogger.keyLifecycle(actor, identity.appId(), alias, activeId,
                                "emergency_rotation", "already-rotated");
                        return new RotationRunResponse(alias, true, true, activeId, "already-rotated");
                    }
                }
            }
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Emergency rotation could not complete; retry the request");
        });
    }

    private void revokeCompromisedKey(AppIdentity identity, String alias, String keyId) {
        JsonNode record = requireRegistry(identity, alias);
        if (keyId.equals(record.path("data").path("activeKeyId").asText())) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Compromised key is still active");
        }
        ObjectNode key = findKey(record, keyId);
        if (key == null || "revoked".equals(key.path("state").asText())) return;
        if (!"verify-only".equals(key.path("state").asText())) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Compromised key is not eligible for revocation");
        }
        ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
        ObjectNode compromised = requireKey(snapshot, keyId);
        compromised.put("state", "revoked");
        compromised.remove("publicKey");
        writeRegistry(identity, alias, snapshot, record.path("version").asLong());
        auditLogger.keyLifecycle(identity.appId(), alias, keyId, "revoke_compromised_key", "success");
    }

    private String ensurePendingThenActivate(AppIdentity identity, String alias, String type, boolean revokeOld) {
        JsonNode record = requireRegistry(identity, alias);
        String pendingId = record.path("data").path("pendingKeyId").asText("");
        if (pendingId.isBlank()) {
            pendingId = createPending(identity, alias, type).keyId();
        } else {
            ObjectNode pending = findKey(record, pendingId);
            if (pending != null && "creating".equals(pending.path("state").asText())) {
                createPending(identity, alias, type);
            }
        }
        activate(identity, alias, pendingId, revokeOld);
        return pendingId;
    }

    /** Stage an exportable replacement key without changing the active version. */
    public KeyResponse createPending(AppIdentity identity, String alias, String type) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateType(type);
        return withLock(identity, alias, () -> {
            JsonNode record = readRegistry(identity, alias);
            if (record == null) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Create the initial key pair before rotating it");
            }
            ensureType(record, type);
            String pendingId = record.path("data").path("pendingKeyId").asText("");
            if (!pendingId.isBlank()) {
                ObjectNode pending = findKey(record, pendingId);
                if (pending != null && "creating".equals(pending.path("state").asText())
                        && type.equals(pending.path("type").asText())) {
                    finishPendingCreation(identity, alias, pendingId);
                    return pair(identity, alias, requireKey(readRegistry(identity, alias), pendingId), false);
                }
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "A rotation is already pending for this key alias");
            }

            for (JsonNode key : record.path("data").path("keys")) {
                String state = key.path("state").asText();
                if ("pending".equals(state) || "creating".equals(state)) {
                    throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                            "A pending rotation must be activated or canceled before another can be requested");
                }
            }

            ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
            int nextVersion = 1;
            for (JsonNode key : snapshot.path("keys")) {
                nextVersion = Math.max(nextVersion, key.path("version").asInt() + 1);
            }
            String keyId = "v" + nextVersion;
            String transitName = "rotation-" + UUID.randomUUID().toString().replace("-", "");
            ObjectNode pending = mapper.createObjectNode();
            pending.put("keyId", keyId);
            pending.put("version", nextVersion);
            pending.put("type", type);
            pending.put("transitName", transitName);
            pending.put("state", "creating");
            pending.put("createdAt", Instant.now().toString());
            snapshot.withArray("keys").add(pending);
            snapshot.put("pendingKeyId", keyId);
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());

            finishPendingCreation(identity, alias, keyId);
            JsonNode updated = readRegistry(identity, alias);
            return pair(identity, alias, requireKey(updated, keyId), false);
        });
    }

    public KeyResponse readPending(AppIdentity identity, String alias, String keyId) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateKeyId(keyId);
        return withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            ObjectNode pending = findKey(record, keyId);
            if (pending == null || !"pending".equals(pending.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Pending key not found");
            }
            return pair(identity, alias, pending, false);
        });
    }

    /** Return public verification material only; revoked key entries never expose their key bytes. */
    public List<PublicKeyEntry> publicKeys(AppIdentity identity, String alias) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        JsonNode record = requireRegistry(identity, alias);
        List<PublicKeyEntry> result = new ArrayList<>();
        for (JsonNode key : record.path("data").path("keys")) {
            String state = key.path("state").asText();
            if ("creating".equals(state)) continue;
            String publicKey = "revoked".equals(state) ? null : key.path("publicKey").asText(null);
            result.add(new PublicKeyEntry(key.path("keyId").asText(), key.path("type").asText(), state,
                    key.path("createdAt").asText(), publicKey));
        }
        return result;
    }

    /** Activate a staged exportable key while retaining the previous public key for verification. */
    public void activate(AppIdentity identity, String alias, String keyId) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateKeyId(keyId);
        activate(identity, alias, keyId, false);
    }

    private void activate(AppIdentity identity, String alias, String keyId, boolean revokeOld) {
        withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
            ObjectNode pending = findKey(snapshot, keyId);
            if (pending == null || !"pending".equals(pending.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Pending key creation is not complete");
            }
            JsonNode transitKey = openBao.getOrNull(identity, transitKeyPath(pending.path("transitName").asText()));
            if (transitKey == null || !transitKey.path("data").path("exportable").asBoolean(false)) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                        "Pending key is non-exportable; cancel it and stage a new key before activation");
            }
            ObjectNode active = requireKey(snapshot, snapshot.path("activeKeyId").asText());
            active.put("state", revokeOld ? "revoked" : "verify-only");
            if (revokeOld) active.remove("publicKey");
            for (JsonNode candidateNode : snapshot.path("keys")) {
                ObjectNode candidate = (ObjectNode) candidateNode;
                if (!keyId.equals(candidate.path("keyId").asText())
                        && ("pending".equals(candidate.path("state").asText())
                        || "creating".equals(candidate.path("state").asText()))) {
                    candidate.put("state", "abandoned");
                    candidate.remove("publicKey");
                }
            }
            pending.put("state", "active");
            snapshot.put("activeKeyId", keyId);
            snapshot.putNull("pendingKeyId");
            snapshot.with("rotationPolicy").put("lastRotatedAt", Instant.now().toString());
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());
            auditLogger.keyLifecycle(identity.appId(), alias, keyId,
                    revokeOld ? "emergency_activate_revoke_old" : "activate", "success");
            return null;
        });
    }

    public void cancelPending(AppIdentity identity, String alias, String keyId) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateKeyId(keyId);
        withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            if (!keyId.equals(record.path("data").path("pendingKeyId").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Pending key not found");
            }
            ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
            ObjectNode pending = requireKey(snapshot, keyId);
            if (!"pending".equals(pending.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Pending key creation is not complete");
            }
            pending.put("state", "abandoned");
            pending.remove("publicKey");
            snapshot.putNull("pendingKeyId");
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());
            auditLogger.keyLifecycle(identity.appId(), alias, keyId, "cancel_rotation", "success");
            return null;
        });
    }

    public void revokePublicKey(AppIdentity identity, String alias, String keyId) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        validateKeyId(keyId);
        withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            if (keyId.equals(record.path("data").path("activeKeyId").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "The active key cannot be revoked");
            }
            if (keyId.equals(record.path("data").path("pendingKeyId").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Cancel the pending rotation before revoking a prior key");
            }
            ObjectNode snapshot = (ObjectNode) record.path("data").deepCopy();
            ObjectNode key = findKey(snapshot, keyId);
            if (key == null || !"verify-only".equals(key.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Prior public key not found");
            }
            key.put("state", "revoked");
            key.remove("publicKey");
            writeRegistry(identity, alias, snapshot, record.path("version").asLong());
            auditLogger.keyLifecycle(identity.appId(), alias, keyId, "revoke_public_key", "success");
            return null;
        });
    }

    /** Delete all Transit material tracked by an alias and then remove its KV registry. */
    public void deleteKeyPair(AppIdentity identity, String alias) {
        ensureAppIdentity(identity);
        validateAlias(alias);
        withLock(identity, alias, () -> {
            JsonNode record = requireRegistry(identity, alias);
            for (JsonNode key : record.path("data").path("keys")) {
                String transitName = key.path("transitName").asText("");
                if (transitName.isBlank()) {
                    throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                            "Key registry contains a version without a Transit key name");
                }

                String transitPath = transitKeyPath(transitName);
                if (openBao.getOrNull(identity, transitPath) != null) {
                    openBao.post(identity, transitPath + "/config", Map.of("deletion_allowed", true));
                    openBao.delete(identity, transitPath);
                }
            }

            openBao.delete(identity, "/v1/" + kvMount + "/metadata/_internal/key-registry/" + alias);
            auditLogger.keyLifecycle(identity.appId(), alias, "all", "delete_key_pair", "success");
            return null;
        });
    }

    private JsonNode initializeRegistry(AppIdentity identity, String alias, String type) {
        String transitName = alias;
        String transitPath = transitKeyPath(transitName);
        JsonNode transitKey = openBao.getOrNull(identity, transitPath);
        if (transitKey == null) {
            openBao.post(identity, transitPath, Map.of("type", type, "exportable", true));
        } else {
            if (!type.equals(transitKey.path("data").path("type").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "A key with this name already exists with another type");
            }
            if (!transitKey.path("data").path("exportable").asBoolean(false)) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                        "Existing key is non-exportable; migrate to a new alias to retrieve private key material");
            }
        }
        ObjectNode metadata = mapper.createObjectNode();
        metadata.put("alias", alias);
        metadata.put("type", type);
        metadata.put("activeKeyId", "v1");
        metadata.putNull("pendingKeyId");
        ObjectNode policy = metadata.putObject("rotationPolicy");
        policy.put("enabled", false);
        policy.put("intervalSeconds", 0);
        policy.put("lastRotatedAt", Instant.now().toString());
        ArrayNode keys = metadata.putArray("keys");
        ObjectNode initial = keys.addObject();
        initial.put("keyId", "v1");
        initial.put("version", 1);
        initial.put("type", type);
        initial.put("transitName", transitName);
        initial.put("state", "active");
        initial.put("createdAt", Instant.now().toString());
        initial.put("publicKey", export(identity, transitName, "public-key"));
        try {
            writeRegistry(identity, alias, metadata, 0);
            return metadataEnvelope(metadata, 1);
        } catch (ResponseStatusException exception) {
            if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE) throw exception;
            JsonNode winner = readRegistry(identity, alias);
            if (winner == null) throw exception;
            ensureType(winner, type);
            return winner;
        }
    }

    private void finishPendingCreation(AppIdentity identity, String alias, String keyId) {
        JsonNode record = requireRegistry(identity, alias);
        ObjectNode pending = requireKey(record, keyId);
        String transitName = pending.path("transitName").asText();
        JsonNode transitKey = openBao.getOrNull(identity, transitKeyPath(transitName));
        if (transitKey == null) {
            openBao.post(identity, transitKeyPath(transitName),
                    Map.of("type", pending.path("type").asText(), "exportable", true));
        } else if (!transitKey.path("data").path("exportable").asBoolean(false)) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                    "Pending Transit key is non-exportable; cancel it and stage a new key");
        }
        String publicKey = export(identity, transitName, "public-key");
        for (int attempt = 0; attempt < 5; attempt++) {
            JsonNode latest = requireRegistry(identity, alias);
            ObjectNode latestPending = findKey((ObjectNode) latest.path("data"), keyId);
            if (latestPending == null) throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Pending key was removed");
            if ("pending".equals(latestPending.path("state").asText())) return;
            if (!"creating".equals(latestPending.path("state").asText())) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Pending key is not available");
            }
            ObjectNode snapshot = (ObjectNode) latest.path("data").deepCopy();
            ObjectNode toUpdate = requireKey(snapshot, keyId);
            toUpdate.put("publicKey", publicKey);
            toUpdate.put("state", "pending");
            try {
                writeRegistry(identity, alias, snapshot, latest.path("version").asLong());
                auditLogger.keyLifecycle(identity.appId(), alias, keyId, "stage", "success");
                return;
            } catch (ResponseStatusException exception) {
                if (exception.getStatusCode().value() != HttpStatusCodes.CONFLICT_CODE || attempt == 4) throw exception;
            }
        }
    }

    private KeyResponse pair(AppIdentity identity, String alias, ObjectNode key, boolean includePrivate) {
        String transitName = key.path("transitName").asText();
        if (includePrivate) {
            JsonNode transit = openBao.getOrNull(identity, transitKeyPath(transitName));
            if (transit == null || !transit.path("data").path("exportable").asBoolean(false)) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT,
                        "This key is non-exportable; rotate to a new key before retrieving its private key");
            }
        }
        return new KeyResponse(alias, key.path("type").asText(),
                key.path("keyId").asText(), export(identity, transitName, "public-key"),
                includePrivate ? export(identity, transitName, "private-key") : null);
    }

    private String export(AppIdentity identity, String transitName, String kind) {
        JsonNode response = openBao.getWithQuery(identity,
                "/v1/" + transitMount + "/export/" + kind + "/" + transitName + "/latest", "format", "pem");
        JsonNode keys = response.path("data").path("keys");
        JsonNode key = keys.path("latest");
        if (key.isMissingNode() && keys.isObject() && keys.size() > 0) key = keys.elements().next();
        if (key.isMissingNode() || key.isNull()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_GATEWAY, "OpenBao did not return key material");
        }
        return key.asText();
    }

    private JsonNode readRegistry(AppIdentity identity, String alias) {
        JsonNode response = openBao.getOrNull(identity, registryPath(alias));
        if (response == null) return null;
        return metadataEnvelope(response.path("data").path("data"),
                response.path("data").path("metadata").path("version").asLong());
    }

    private JsonNode requireRegistry(AppIdentity identity, String alias) {
        JsonNode record = readRegistry(identity, alias);
        if (record == null) throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Key alias not found");
        return record;
    }

    private void writeRegistry(AppIdentity identity, String alias, JsonNode data, long expectedVersion) {
        openBao.putKvV2Cas(identity, registryPath(alias), data, expectedVersion);
    }

    private String registryPath(String alias) {
        validateAlias(alias);
        return "/v1/" + kvMount + "/data/_internal/key-registry/" + alias;
    }

    private String transitKeyPath(String transitName) {
        return "/v1/" + transitMount + "/keys/" + transitName;
    }

    private JsonNode metadataEnvelope(JsonNode data, long version) {
        ObjectNode envelope = mapper.createObjectNode();
        envelope.set("data", data.deepCopy());
        envelope.put("version", version);
        return envelope;
    }

    private void ensureType(JsonNode record, String type) {
        if (!type.equals(record.path("data").path("type").asText())) {
            throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "Key alias already uses another type; use a new alias");
        }
    }

    private ObjectNode findKey(JsonNode metadata, String keyId) {
        for (JsonNode key : metadata.path("data").path("keys")) {
            if (keyId.equals(key.path("keyId").asText())) return (ObjectNode) key;
        }
        // The node may already be the registry data object rather than the KV response envelope.
        for (JsonNode key : metadata.path("keys")) {
            if (keyId.equals(key.path("keyId").asText())) return (ObjectNode) key;
        }
        return null;
    }

    private ObjectNode requireKey(JsonNode metadata, String keyId) {
        ObjectNode key = findKey(metadata, keyId);
        if (key == null) throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Key version not found");
        return key;
    }

    /** Enforce app-scoped access before using an app OpenBao token or namespace. */
    private void ensureAppIdentity(AppIdentity identity) {
        if (identity == null || identity.registration() == null || identity.adminUser() || identity.rotationOperator()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "An app-scoped identity is required for this key operation");
        }
    }

    /** Resolve an emergency request to its owning app without allowing app identities to cross namespaces. */
    private AppIdentity resolveEmergencyTarget(AppIdentity caller, EmergencyRotationRequest request) {
        if (caller == null || caller.adminUser()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "Use an app identity or rotation-operator identity for emergency rotation");
        }
        String requestedApp = request == null ? null : request.targetAppId();
        if (caller.rotationOperator()) {
            if (requestedApp == null || !requestedApp.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
                throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST,
                        "A valid targetAppId is required for operator rotation");
            }
            VaultServiceProperties.AppRegistration registration = properties.getIam().getApps().get(requestedApp);
            if (registration == null) throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "Target app not found");
            return new AppIdentity(requestedApp, registration);
        }
        ensureAppIdentity(caller);
        if (requestedApp != null && !caller.appId().equals(requestedApp)) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "Apps can rotate keys only in their own namespace");
        }
        return caller;
    }

    /** Validate a key alias before it is used in a KV or Transit path. */
    private void validateAlias(String alias) {
        if (alias == null || !ALIAS.matcher(alias).matches()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Invalid key alias");
        }
    }

    /** Validate a key version identifier before registry lookup. */
    private void validateKeyId(String keyId) {
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Invalid key ID");
        }
    }

    /** Restrict key generation to configured OpenBao asymmetric algorithms. */
    private void validateType(String type) {
        if (type == null || !TRANSIT_TYPES.contains(type) || !supportedTypes.contains(type)) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Unsupported asymmetric key type");
        }
    }

    private <T> T withLock(AppIdentity identity, String alias, Operation<T> operation) {
        String lockKey = identity.appId() + ":" + alias;
        ReentrantLock lock = locks.computeIfAbsent(lockKey, ignored -> new ReentrantLock());
        lock.lock();
        try {
            return operation.run();
        } finally {
            lock.unlock();
        }
    }

    @FunctionalInterface
    private interface Operation<T> { T run(); }

}
