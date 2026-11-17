package com.khalid.vault.secret;

import com.khalid.vault.common.HttpStatusCodes;
import com.khalid.vault.dto.secret.SecretReadResponse;
import com.khalid.vault.dto.secret.SecretWriteRequest;
import com.khalid.vault.dto.secret.SecretWriteResponse;
import com.khalid.vault.iam.AppIdentity;
import com.khalid.vault.iam.AppIdentityFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretController {
    private final SecretService secretService;

    public SecretController(SecretService secretService) {
        this.secretService = secretService;
    }

    @GetMapping("/{name}")
    public SecretReadResponse read(@PathVariable String name, HttpServletRequest request) {
        return secretService.read(appIdentity(request), name);
    }

    @PutMapping("/{name}")
    public SecretWriteResponse write(@PathVariable String name, @Valid @RequestBody SecretWriteRequest body,
                                     HttpServletRequest request) {
        return secretService.write(appIdentity(request), name, body);
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> delete(@PathVariable String name, HttpServletRequest request) {
        secretService.delete(appIdentity(request), name);
        return ResponseEntity.status(HttpStatusCodes.NO_CONTENT).build();
    }

    private static AppIdentity appIdentity(HttpServletRequest request) {
        return (AppIdentity) request.getAttribute(AppIdentityFilter.IDENTITY_ATTRIBUTE);
    }
}
