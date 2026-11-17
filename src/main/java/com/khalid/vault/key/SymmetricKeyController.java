package com.khalid.vault.key;

import com.khalid.vault.dto.key.SymmetricKeyRequest;
import com.khalid.vault.dto.key.SymmetricKeyResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.iam.AppIdentityFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/symmetric-keys")
public class SymmetricKeyController {
    private final SymmetricKeyService symmetricKeyService;

    public SymmetricKeyController(SymmetricKeyService symmetricKeyService) {
        this.symmetricKeyService = symmetricKeyService;
    }

    @PostMapping("/{alias}")
    public SymmetricKeyResponse requestKey(@PathVariable String alias,
                                           @Valid @RequestBody SymmetricKeyRequest body,
                                           HttpServletRequest request,
                                           HttpServletResponse response) {
        noStore(response);
        return symmetricKeyService.requestKey(identity(request), alias, body.expirationEnabled());
    }

    @GetMapping("/{alias}/versions/{keyId}")
    public SymmetricKeyResponse getVersion(@PathVariable String alias, @PathVariable String keyId,
                                           HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        return symmetricKeyService.getVersion(identity(request), alias, keyId);
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
    }

    private static AppIdentity identity(HttpServletRequest request) {
        return (AppIdentity) request.getAttribute(AppIdentityFilter.IDENTITY_ATTRIBUTE);
    }
}
