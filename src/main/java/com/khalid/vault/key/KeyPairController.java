package com.khalid.vault.key;

import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.dto.key.EmergencyRotationRequest;
import com.khalid.vault.dto.key.KeyPairRequest;
import com.khalid.vault.dto.key.KeyResponse;
import com.khalid.vault.dto.key.PolicyResponse;
import com.khalid.vault.dto.key.PublicKeyEntry;
import com.khalid.vault.dto.key.RotationPolicyRequest;
import com.khalid.vault.dto.key.RotationRunResponse;
import com.khalid.vault.dto.key.RotationStatusResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.iam.AppIdentityFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/keys")
public class KeyPairController {
    private final KeyRotationService rotationService;

    public KeyPairController(KeyRotationService rotationService) {
        this.rotationService = rotationService;
    }

    @GetMapping("/types")
    public Set<String> types() { return rotationService.supportedTypes(); }

    @PostMapping("/{name}")
    public KeyResponse getOrCreate(@PathVariable String name, @Valid @RequestBody KeyPairRequest body,
                                   HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        return rotationService.getOrCreateActive(identity(request), name, body.type());
    }

    @GetMapping("/{name}/key-pair")
    public KeyResponse activePair(@PathVariable String name, HttpServletRequest request,
                                  HttpServletResponse response) {
        noStore(response);
        return rotationService.getActivePair(identity(request), name);
    }

    @GetMapping("/{name}/rotation-policy")
    public PolicyResponse getRotationPolicy(@PathVariable String name, HttpServletRequest request) {
        return rotationService.getPolicy(identity(request), name);
    }

    @PutMapping("/{name}/rotation-policy")
    public PolicyResponse setRotationPolicy(@PathVariable String name,
            @Valid @RequestBody RotationPolicyRequest body, HttpServletRequest request) {
        return rotationService.updatePolicy(identity(request), name, body.enabled(), body.intervalSeconds());
    }

    @PostMapping("/{name}/rotation-policy/run")
    public RotationRunResponse runRotationPolicy(@PathVariable String name, HttpServletRequest request) {
        return rotationService.runPolicy(identity(request), name);
    }

    @PostMapping("/{name}/emergency-rotation")
    public RotationRunResponse emergencyRotation(@PathVariable String name,
            @RequestBody(required = false) EmergencyRotationRequest body, HttpServletRequest request) {
        return rotationService.emergencyRotate(identity(request), name, body);
    }

    @PostMapping("/{name}/rotations")
    public KeyResponse stageRotation(@PathVariable String name, @Valid @RequestBody KeyPairRequest body,
                                     HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        return rotationService.createPending(identity(request), name, body.type());
    }

    @GetMapping("/{name}/rotations/{keyId}")
    public KeyResponse readPending(@PathVariable String name, @PathVariable String keyId,
                                   HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        return rotationService.readPending(identity(request), name, keyId);
    }

    @PostMapping("/{name}/rotations/{keyId}/activate")
    public RotationStatusResponse activate(@PathVariable String name, @PathVariable String keyId,
                                           HttpServletRequest request) {
        rotationService.activate(identity(request), name, keyId);
        return new RotationStatusResponse(name, keyId, "active");
    }

    @DeleteMapping("/{name}/rotations/{keyId}")
    public ResponseEntity<Void> cancelRotation(@PathVariable String name, @PathVariable String keyId,
                                               HttpServletRequest request) {
        rotationService.cancelPending(identity(request), name, keyId);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    @GetMapping("/{name}/public-keys")
    public List<PublicKeyEntry> publicKeys(@PathVariable String name, HttpServletRequest request) {
        return rotationService.publicKeys(identity(request), name);
    }

    @DeleteMapping("/{name}/public-keys/{keyId}")
    public ResponseEntity<Void> revokePublicKey(@PathVariable String name, @PathVariable String keyId,
                                                HttpServletRequest request) {
        rotationService.revokePublicKey(identity(request), name, keyId);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> deleteKeyPair(@PathVariable String name, HttpServletRequest request) {
        rotationService.deleteKeyPair(identity(request), name);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
    }

    private static AppIdentity identity(HttpServletRequest request) {
        return (AppIdentity) request.getAttribute(AppIdentityFilter.IDENTITY_ATTRIBUTE);
    }

}
