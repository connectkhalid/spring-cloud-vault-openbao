package com.khalid.vault.secret;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.dto.secret.SecretReadResponse;
import com.khalid.vault.dto.secret.SecretWriteRequest;
import com.khalid.vault.dto.secret.SecretWriteResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.openbao.OpenBaoClient;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.regex.Pattern;

@Service
public class SecretService {
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private final OpenBaoClient openBao;
    private final ObjectMapper mapper;
    private final String mount;

    public SecretService(OpenBaoClient openBao, ObjectMapper mapper, VaultServiceProperties properties) {
        this.openBao = openBao;
        this.mapper = mapper;
        this.mount = properties.getOpenbao().getKvMount();
    }

    /** Read an app-scoped secret after validating the path name in the service boundary. */
    public SecretReadResponse read(AppIdentity identity, String name) {
        ensureAppIdentity(identity);
        validateName(name);
        JsonNode response = openBao.get(identity, "/v1/" + mount + "/data/" + name);
        Map<String, Object> data = mapper.convertValue(response.path("data").path("data"), new TypeReference<>() { });
        long version = response.path("data").path("metadata").path("version").asLong();
        return new SecretReadResponse(name, data, version);
    }

    /** Write a secret value and return the resulting KV version. */
    public SecretWriteResponse write(AppIdentity identity, String name, SecretWriteRequest body) {
        ensureAppIdentity(identity);
        validateName(name);
        JsonNode response = openBao.post(identity, "/v1/" + mount + "/data/" + name,
                Map.of("data", body.data()));
        return new SecretWriteResponse(name, response.path("data").path("version").asLong());
    }

    /** Delete all KV versions by removing their KV v2 metadata record. */
    public void delete(AppIdentity identity, String name) {
        ensureAppIdentity(identity);
        validateName(name);
        openBao.delete(identity, "/v1/" + mount + "/metadata/" + name);
    }

    /** Reject path traversal and unsupported names before constructing an OpenBao path. */
    private void validateName(String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "Invalid secret name");
        }
    }

    private void ensureAppIdentity(AppIdentity identity) {
        if (identity == null || identity.registration() == null || identity.adminUser() || identity.rotationOperator()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN, "An app-scoped identity is required for secret operations");
        }
    }
}
