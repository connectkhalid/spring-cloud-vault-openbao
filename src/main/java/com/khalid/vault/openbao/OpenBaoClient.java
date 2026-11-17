package com.khalid.vault.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.iam.AppIdentity;
import org.springframework.vault.client.VaultHttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Component
public class OpenBaoClient {
    private final RestClient restClient;
    private final ObjectMapper mapper;
    private final String adminToken;

    public OpenBaoClient(VaultServiceProperties properties, ObjectMapper mapper) {
        this.restClient = RestClient.builder().baseUrl(properties.getOpenbao().getAddress()).build();
        this.mapper = mapper;
        this.adminToken = properties.getOpenbao().getAdminToken();
    }

    public JsonNode get(AppIdentity identity, String path) {
        return request(identity, "GET", path, null);
    }

    public JsonNode post(AppIdentity identity, String path, Object body) {
        return request(identity, "POST", path, body);
    }

    public JsonNode put(AppIdentity identity, String path, Object body) {
        return request(identity, "PUT", path, body);
    }

    public JsonNode putKvV2Cas(AppIdentity identity, String path, JsonNode data, long expectedVersion) {
        return request(identity, "PUT", path, Map.of(
                "options", Map.of("cas", expectedVersion),
                "data", data), false, true);
    }

    public void delete(AppIdentity identity, String path) {
        request(identity, "DELETE", path, null);
    }

    public void renewToken(AppIdentity identity) {
        JsonNode response = post(identity, "/v1/auth/token/renew-self", Map.of());
        String renewedToken = response.path("auth").path("client_token").asText();
        if (!renewedToken.isBlank()) identity.registration().setOpenbaoToken(renewedToken);
    }

    public JsonNode getOrNull(AppIdentity identity, String path) {
        return request(identity, "GET", path, null, true);
    }

    public JsonNode getWithQuery(AppIdentity identity, String path, String name, String value) {
        String encoded = UriComponentsBuilder.fromPath(path).queryParam(name, value).build().encode().toUriString();
        return request(identity, "GET", encoded, null);
    }

    /** Perform an admin-scoped OpenBao read, optionally in a target namespace. */
    public JsonNode adminGet(String path, String namespace) { return adminRequest("GET", path, null, namespace); }
    public JsonNode adminGetOrNull(String path, String namespace) {
        if (adminToken.isBlank()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "Namespace administration is not configured; set OPENBAO_ADMIN_TOKEN");
        }
        return request("GET", path, null, adminToken, namespace, true, false);
    }
    public JsonNode adminPost(String path, Object body, String namespace) { return adminRequest("POST", path, body, namespace); }
    public JsonNode adminPut(String path, Object body, String namespace) { return adminRequest("PUT", path, body, namespace); }
    public void adminDelete(String path, String namespace) { adminRequest("DELETE", path, null, namespace); }

    private JsonNode request(AppIdentity identity, String method, String path, Object body) {
        return request(identity, method, path, body, false);
    }

    private JsonNode request(AppIdentity identity, String method, String path, Object body, boolean allowNotFound) {
        return request(identity, method, path, body, allowNotFound, false);
    }

    private JsonNode request(AppIdentity identity, String method, String path, Object body,
                             boolean allowNotFound, boolean casUpdate) {
        return request(method, path, body, identity.registration().getOpenbaoToken(),
                identity.registration().getNamespace(), allowNotFound, casUpdate);
    }

    private JsonNode adminRequest(String method, String path, Object body, String namespace) {
        if (adminToken.isBlank()) {
            throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN,
                    "Namespace administration is not configured; set OPENBAO_ADMIN_TOKEN");
        }
        return request(method, path, body, adminToken, namespace, false, false);
    }

    private JsonNode request(String method, String path, Object body, String token, String namespace,
                             boolean allowNotFound, boolean casUpdate) {
        try {
            RestClient.RequestBodySpec request = restClient.method(org.springframework.http.HttpMethod.valueOf(method))
                    .uri(path)
                    .header(VaultHttpHeaders.VAULT_TOKEN, token);
            if (namespace != null && !namespace.isBlank()) {
                request.header(VaultHttpHeaders.VAULT_NAMESPACE, namespace);
            }
            RestClient.ResponseSpec response = body == null ? request.retrieve() : request.body(body).retrieve();
            JsonNode result = response.body(JsonNode.class);
            return result == null ? mapper.createObjectNode() : result;
        } catch (HttpClientErrorException exception) {
            if (allowNotFound && exception.getStatusCode().value() == HttpStatusCodes.NOT_FOUND_CODE) return null;
            if (casUpdate && exception.getStatusCode().value() == HttpStatusCodes.BAD_REQUEST_CODE) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "OpenBao rejected a concurrent or invalid update");
            }
            if (exception.getStatusCode().value() == HttpStatusCodes.BAD_REQUEST_CODE) {
                throw new ResponseStatusException(HttpStatusCodes.BAD_REQUEST, "OpenBao rejected the request as invalid");
            }
            if (exception.getStatusCode().value() == HttpStatusCodes.NOT_FOUND_CODE) {
                throw new ResponseStatusException(HttpStatusCodes.NOT_FOUND, "OpenBao resource not found");
            }
            if (exception.getStatusCode().value() == HttpStatusCodes.FORBIDDEN_CODE) {
                throw new ResponseStatusException(HttpStatusCodes.FORBIDDEN, "OpenBao policy denied this operation");
            }
            if (exception.getStatusCode().value() == HttpStatusCodes.CONFLICT_CODE) {
                throw new ResponseStatusException(HttpStatusCodes.CONFLICT, "OpenBao reports a resource conflict");
            }
            throw new ResponseStatusException(HttpStatusCodes.BAD_GATEWAY, "OpenBao rejected the request");
        } catch (Exception exception) {
            if (exception instanceof ResponseStatusException statusException) throw statusException;
            throw new ResponseStatusException(HttpStatusCodes.BAD_GATEWAY, "OpenBao is unavailable");
        }
    }
}
