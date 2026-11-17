package com.khalid.vault.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.khalid.vault.audit.AuditLoggerService;
import com.khalid.vault.common.ApiException;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.dto.admin.AdminResourceResponse;
import com.khalid.vault.dto.admin.NamespaceRequest;
import com.khalid.vault.dto.admin.PolicyRequest;
import com.khalid.vault.dto.admin.TokenRoleRequest;
import com.khalid.vault.dto.admin.IntegrationIdentityRequest;
import com.khalid.vault.dto.admin.IntegrationIdentityResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.openbao.OpenBaoClient;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class AdminManagementService {
    private static final Pattern RESOURCE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final Pattern NAMESPACE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63})*");
    private static final Pattern OPENBAO_DURATION = Pattern.compile("(?:[0-9]+(?:ns|us|µs|ms|s|m|h))+");
    private final OpenBaoClient openBao;
    private final AuditLoggerService auditLogger;
    private final IntegrationIdentityService integrationIdentities;

    public AdminManagementService(OpenBaoClient openBao, AuditLoggerService auditLogger,
                                  IntegrationIdentityService integrationIdentities) {
        this.openBao = openBao;
        this.auditLogger = auditLogger;
        this.integrationIdentities = integrationIdentities;
    }

    public IntegrationIdentityResponse createIntegrationIdentity(AppIdentity actor, String id, IntegrationIdentityRequest body) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.create(id, body);
        auditLogger.adminAction(actor.appId(), "create_integration_identity", id, "success");
        return result;
    }

    public IntegrationIdentityResponse getIntegrationIdentity(AppIdentity actor, String id) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.read(id);
        auditLogger.adminAction(actor.appId(), "read_integration_identity", id, "success");
        return result;
    }

    public List<IntegrationIdentityResponse> listIntegrationIdentities(AppIdentity actor) {
        requireAdmin(actor);
        List<IntegrationIdentityResponse> result = integrationIdentities.list();
        auditLogger.adminAction(actor.appId(), "list_integration_identities", "all", "success");
        return result;
    }

    public IntegrationIdentityResponse updateIntegrationIdentity(AppIdentity actor, String id, IntegrationIdentityRequest body) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.update(id, body);
        auditLogger.adminAction(actor.appId(), "update_integration_identity", id, "success");
        return result;
    }

    public IntegrationIdentityResponse disableIntegrationIdentity(AppIdentity actor, String id) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.disable(id);
        auditLogger.adminAction(actor.appId(), "disable_integration_identity", id, "success");
        return result;
    }

    public IntegrationIdentityResponse enableIntegrationIdentity(AppIdentity actor, String id) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.enable(id);
        auditLogger.adminAction(actor.appId(), "enable_integration_identity", id, "success");
        return result;
    }

    public IntegrationIdentityResponse rotateIntegrationCredential(AppIdentity actor, String id) {
        requireAdmin(actor);
        IntegrationIdentityResponse result = integrationIdentities.rotateCredential(id);
        auditLogger.adminAction(actor.appId(), "rotate_integration_credential", id, "success");
        return result;
    }

    public void deleteIntegrationIdentity(AppIdentity actor, String id) {
        requireAdmin(actor);
        integrationIdentities.delete(id);
        auditLogger.adminAction(actor.appId(), "delete_integration_identity", id, "success");
    }

    /** Create a child namespace, using the root namespace when parent is omitted. */
    public AdminResourceResponse createNamespace(AppIdentity actor, NamespaceRequest request) {
        requireAdmin(actor);
        validateResourceName(request.name(), "namespace name");
        String parent = request.parent() == null ? "" : request.parent().trim();
        if (!parent.isEmpty() && !NAMESPACE.matcher(parent).matches()) {
            throw badRequest("INVALID_NAMESPACE", "Invalid parent namespace");
        }
        String fullName = parent.isEmpty() ? request.name() : parent + "/" + request.name();
        openBao.adminPost("/v1/sys/namespaces/" + fullName, Map.of(), null);
        auditLogger.adminAction(actor.appId(), "create_namespace", fullName, "success");
        return new AdminResourceResponse(fullName, fullName, "created");
    }

    /** List namespaces through OpenBao using the configured admin token. */
    public JsonNode listNamespaces(AppIdentity actor) {
        requireAdmin(actor);
        JsonNode response = openBao.adminGet("/v1/sys/namespaces?list=true", null);
        auditLogger.adminAction(actor.appId(), "list_namespaces", "all", "success");
        return response;
    }

    /** Create or replace an ACL policy in the requested namespace. */
    public AdminResourceResponse putPolicy(AppIdentity actor, PolicyRequest request) {
        requireAdmin(actor);
        validateNamespace(request.namespace());
        validateResourceName(request.name(), "policy name");
        openBao.adminPut("/v1/sys/policies/acl/" + request.name(), Map.of("policy", request.policy()), request.namespace());
        auditLogger.adminAction(actor.appId(), "save_policy", request.namespace() + "/" + request.name(), "success");
        return new AdminResourceResponse(request.namespace(), request.name(), "saved");
    }

    public JsonNode getPolicy(AppIdentity actor, String namespace, String name) {
        requireAdmin(actor);
        validateNamespace(namespace);
        validateResourceName(name, "policy name");
        JsonNode response = openBao.adminGet("/v1/sys/policies/acl/" + name, namespace);
        auditLogger.adminAction(actor.appId(), "read_policy", namespace + "/" + name, "success");
        return response;
    }

    /** List policy names in a namespace without returning policy bodies. */
    public JsonNode listPolicies(AppIdentity actor, String namespace) {
        requireAdmin(actor);
        validateNamespace(namespace);
        JsonNode response = openBao.adminGet("/v1/sys/policies/acl?list=true", namespace);
        auditLogger.adminAction(actor.appId(), "list_policies", namespace, "success");
        return response;
    }

    public void deletePolicy(AppIdentity actor, String namespace, String name) {
        requireAdmin(actor);
        validateNamespace(namespace);
        validateResourceName(name, "policy name");
        openBao.adminDelete("/v1/sys/policies/acl/" + name, namespace);
        auditLogger.adminAction(actor.appId(), "delete_policy", namespace + "/" + name, "success");
    }

    /** Create or replace an OpenBao token role that assigns approved ACL policies. */
    public AdminResourceResponse putTokenRole(AppIdentity actor, TokenRoleRequest request) {
        requireAdmin(actor);
        validateNamespace(request.namespace());
        validateResourceName(request.name(), "role name");
        validatePositiveDuration(request.period());
        Set<String> policies = request.allowedPolicies();
        if (policies == null || policies.isEmpty() || policies.stream().anyMatch(name -> !RESOURCE_NAME.matcher(name).matches())) {
            throw badRequest("INVALID_ROLE_POLICIES", "Role must contain valid allowed policy names");
        }
        if (policies.stream().anyMatch("root"::equalsIgnoreCase)) {
            throw badRequest("ROOT_POLICY_FORBIDDEN", "Token roles cannot grant the root policy");
        }
        for (String policy : policies) {
            if (!"default".equals(policy)) openBao.adminGet("/v1/sys/policies/acl/" + policy, request.namespace());
        }
        openBao.adminPost("/v1/auth/token/roles/" + request.name(), Map.of(
                "allowed_policies", new ArrayList<>(policies),
                "period", request.period(),
                "orphan", request.orphan()), request.namespace());
        auditLogger.adminAction(actor.appId(), "save_token_role", request.namespace() + "/" + request.name(), "success");
        return new AdminResourceResponse(request.namespace(), request.name(), "saved");
    }

    public JsonNode getTokenRole(AppIdentity actor, String namespace, String name) {
        requireAdmin(actor);
        validateNamespace(namespace);
        validateResourceName(name, "role name");
        JsonNode response = openBao.adminGet("/v1/auth/token/roles/" + name, namespace);
        auditLogger.adminAction(actor.appId(), "read_token_role", namespace + "/" + name, "success");
        return response;
    }

    /** List token role names in a namespace. */
    public JsonNode listTokenRoles(AppIdentity actor, String namespace) {
        requireAdmin(actor);
        validateNamespace(namespace);
        JsonNode response = openBao.adminGet("/v1/auth/token/roles?list=true", namespace);
        auditLogger.adminAction(actor.appId(), "list_token_roles", namespace, "success");
        return response;
    }

    public void deleteTokenRole(AppIdentity actor, String namespace, String name) {
        requireAdmin(actor);
        validateNamespace(namespace);
        validateResourceName(name, "role name");
        openBao.adminDelete("/v1/auth/token/roles/" + name, namespace);
        auditLogger.adminAction(actor.appId(), "delete_token_role", namespace + "/" + name, "success");
    }

    private void requireAdmin(AppIdentity actor) {
        if (actor == null || !actor.adminUser()) {
            throw new ApiException(HttpStatusCodes.FORBIDDEN, "ADMIN_REQUIRED", "Administrator role is required");
        }
    }

    private void validateNamespace(String namespace) {
        if (namespace == null || !NAMESPACE.matcher(namespace).matches()) {
            throw badRequest("INVALID_NAMESPACE", "Invalid namespace path");
        }
    }

    private void validateResourceName(String name, String field) {
        if (name == null || !RESOURCE_NAME.matcher(name).matches()) {
            throw badRequest("INVALID_RESOURCE_NAME", "Invalid " + field);
        }
    }

    private void validatePositiveDuration(String value) {
        if (value == null || !OPENBAO_DURATION.matcher(value).matches()
                || value.matches("(?:0+(?:ns|us|µs|ms|s|m|h))+") ) {
            throw badRequest("INVALID_ROLE_PERIOD", "Role period must use OpenBao duration format, for example 24h or 1h30m");
        }
    }

    private ApiException badRequest(String code, String message) {
        return new ApiException(HttpStatusCodes.BAD_REQUEST, code, message);
    }
}
