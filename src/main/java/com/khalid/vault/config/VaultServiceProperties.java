package com.khalid.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Validated
@ConfigurationProperties(prefix = "vault-service")
public class VaultServiceProperties {
    @Valid @NotNull
    private final OpenBao openbao = new OpenBao();
    @Valid @NotNull
    private final Iam iam = new Iam();
    @Valid @NotNull
    private final SymmetricKeys symmetricKeys = new SymmetricKeys();

    public OpenBao getOpenbao() { return openbao; }
    public Iam getIam() { return iam; }
    public SymmetricKeys getSymmetricKeys() { return symmetricKeys; }

    public static class SymmetricKeys {
        @NotNull private Duration defaultTtl = Duration.ofDays(30);
        @NotNull private Duration renewalWindow = Duration.ofHours(24);

        public Duration getDefaultTtl() { return defaultTtl; }
        public void setDefaultTtl(Duration defaultTtl) { this.defaultTtl = defaultTtl; }
        public Duration getRenewalWindow() { return renewalWindow; }
        public void setRenewalWindow(Duration renewalWindow) { this.renewalWindow = renewalWindow; }
    }

    public static class OpenBao {
        @NotBlank private String address = "http://127.0.0.1:8200";
        @NotBlank private String kvMount = "secret";
        @NotBlank private String transitMount = "transit";
        @NotEmpty private Set<String> supportedKeyTypes = new LinkedHashSet<>();
        private String adminToken = "";

        public String getAddress() { return address; }
        public void setAddress(String address) { this.address = address; }

        public String getKvMount() { return kvMount; }
        public void setKvMount(String kvMount) { this.kvMount = kvMount; }

        public String getTransitMount() { return transitMount; }
        public void setTransitMount(String transitMount) { this.transitMount = transitMount; }

        public Set<String> getSupportedKeyTypes() { return supportedKeyTypes; }
        public void setSupportedKeyTypes(Set<String> supportedKeyTypes) { this.supportedKeyTypes = supportedKeyTypes; }

        public String getAdminToken() { return adminToken; }
        public void setAdminToken(String adminToken) { this.adminToken = adminToken; }
    }

    public static class Iam {
        @NotBlank private String signingSecret;
        private String rotationOperatorSecret = "";
        private String adminUsername = "";
        private String adminPassword = "";
        private String identityRegistryNamespace = "";
        @NotNull private Duration tokenTtl = Duration.ofMinutes(15);
        @NotEmpty private Map<String, AppRegistration> apps = new LinkedHashMap<>();

        public String getSigningSecret() { return signingSecret; }
        public void setSigningSecret(String signingSecret) { this.signingSecret = signingSecret; }

        public String getRotationOperatorSecret() { return rotationOperatorSecret; }
        public void setRotationOperatorSecret(String rotationOperatorSecret) { this.rotationOperatorSecret = rotationOperatorSecret; }

        public String getAdminUsername() { return adminUsername; }
        public void setAdminUsername(String adminUsername) { this.adminUsername = adminUsername; }

        public String getAdminPassword() { return adminPassword; }
        public void setAdminPassword(String adminPassword) { this.adminPassword = adminPassword; }

        public String getIdentityRegistryNamespace() { return identityRegistryNamespace; }
        public void setIdentityRegistryNamespace(String identityRegistryNamespace) { this.identityRegistryNamespace = identityRegistryNamespace; }

        public Duration getTokenTtl() { return tokenTtl; }
        public void setTokenTtl(Duration tokenTtl) { this.tokenTtl = tokenTtl; }

        public Map<String, AppRegistration> getApps() { return apps; }
        public void setApps(Map<String, AppRegistration> apps) { this.apps = apps; }
    }

    public static class AppRegistration {
        @NotBlank private String clientSecret;
        @NotBlank private String namespace;
        @NotBlank private volatile String openbaoToken;

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public String getNamespace() { return namespace; }
        public void setNamespace(String namespace) { this.namespace = namespace; }

        public String getOpenbaoToken() { return openbaoToken; }
        public void setOpenbaoToken(String openbaoToken) { this.openbaoToken = openbaoToken; }
    }
}
