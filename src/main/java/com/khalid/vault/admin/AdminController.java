package com.khalid.vault.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.dto.admin.AdminResourceResponse;
import com.khalid.vault.dto.admin.NamespaceRequest;
import com.khalid.vault.dto.admin.PolicyRequest;
import com.khalid.vault.dto.admin.TokenRoleRequest;
import com.khalid.vault.dto.admin.IntegrationIdentityRequest;
import com.khalid.vault.dto.admin.IntegrationIdentityResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.iam.AppIdentityFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.http.CacheControl;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final AdminManagementService adminService;

    public AdminController(AdminManagementService adminService) {
        this.adminService = adminService;
    }

    @PostMapping("/namespaces")
    public AdminResourceResponse createNamespace(@Valid @RequestBody NamespaceRequest body,
                                                 HttpServletRequest request) {
        return adminService.createNamespace(identity(request), body);
    }

    @GetMapping("/namespaces")
    public JsonNode namespaces(HttpServletRequest request) {
        return adminService.listNamespaces(identity(request));
    }

    @PostMapping("/identities/{id}")
    public ResponseEntity<IntegrationIdentityResponse> createIdentity(@PathVariable String id,
                                                                       @Valid @RequestBody IntegrationIdentityRequest body,
                                                                       HttpServletRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(adminService.createIntegrationIdentity(identity(request), id, body));
    }

    @GetMapping("/identities")
    public java.util.List<IntegrationIdentityResponse> identities(HttpServletRequest request) {
        return adminService.listIntegrationIdentities(identity(request));
    }

    @GetMapping("/identities/{id}")
    public IntegrationIdentityResponse identity(@PathVariable String id, HttpServletRequest request) {
        return adminService.getIntegrationIdentity(identity(request), id);
    }

    @PutMapping("/identities/{id}")
    public IntegrationIdentityResponse updateIdentity(@PathVariable String id,
                                                        @Valid @RequestBody IntegrationIdentityRequest body,
                                                        HttpServletRequest request) {
        return adminService.updateIntegrationIdentity(identity(request), id, body);
    }

    @PostMapping("/identities/{id}/disable")
    public IntegrationIdentityResponse disableIdentity(@PathVariable String id, HttpServletRequest request) {
        return adminService.disableIntegrationIdentity(identity(request), id);
    }

    @PostMapping("/identities/{id}/enable")
    public IntegrationIdentityResponse enableIdentity(@PathVariable String id, HttpServletRequest request) {
        return adminService.enableIntegrationIdentity(identity(request), id);
    }

    @PostMapping("/identities/{id}/rotate-secret")
    public ResponseEntity<IntegrationIdentityResponse> rotateIdentitySecret(@PathVariable String id, HttpServletRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(adminService.rotateIntegrationCredential(identity(request), id));
    }

    @DeleteMapping("/identities/{id}")
    public ResponseEntity<Void> deleteIdentity(@PathVariable String id, HttpServletRequest request) {
        adminService.deleteIntegrationIdentity(identity(request), id);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    @PutMapping("/policies")
    public AdminResourceResponse savePolicy(@Valid @RequestBody PolicyRequest body,
                                            HttpServletRequest request) {
        return adminService.putPolicy(identity(request), body);
    }

    @GetMapping("/policies")
    public JsonNode policy(@RequestParam String namespace, @RequestParam String name,
                           HttpServletRequest request) {
        return adminService.getPolicy(identity(request), namespace, name);
    }

    @GetMapping("/policies/list")
    public JsonNode policies(@RequestParam String namespace, HttpServletRequest request) {
        return adminService.listPolicies(identity(request), namespace);
    }

    @DeleteMapping("/policies")
    public ResponseEntity<Void> deletePolicy(@RequestParam String namespace, @RequestParam String name,
                                             HttpServletRequest request) {
        adminService.deletePolicy(identity(request), namespace, name);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    @PutMapping("/roles")
    public AdminResourceResponse saveRole(@Valid @RequestBody TokenRoleRequest body,
                                          HttpServletRequest request) {
        return adminService.putTokenRole(identity(request), body);
    }

    @GetMapping("/roles")
    public JsonNode role(@RequestParam String namespace, @RequestParam String name,
                         HttpServletRequest request) {
        return adminService.getTokenRole(identity(request), namespace, name);
    }

    @GetMapping("/roles/list")
    public JsonNode roles(@RequestParam String namespace, HttpServletRequest request) {
        return adminService.listTokenRoles(identity(request), namespace);
    }

    @DeleteMapping("/roles")
    public ResponseEntity<Void> deleteRole(@RequestParam String namespace, @RequestParam String name,
                                           HttpServletRequest request) {
        adminService.deleteTokenRole(identity(request), namespace, name);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    private static AppIdentity identity(HttpServletRequest request) {
        return (AppIdentity) request.getAttribute(AppIdentityFilter.IDENTITY_ATTRIBUTE);
    }
}
