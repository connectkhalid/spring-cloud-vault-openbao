package com.khalid.vault.iam;

import com.khalid.vault.config.VaultServiceProperties;

public record AppIdentity(String appId, VaultServiceProperties.AppRegistration registration,
                          boolean rotationOperator, boolean adminUser) {
    public AppIdentity(String appId, VaultServiceProperties.AppRegistration registration) {
        this(appId, registration, false, false);
    }

    public AppIdentity(String appId, VaultServiceProperties.AppRegistration registration, boolean rotationOperator) {
        this(appId, registration, rotationOperator, false);
    }
}
