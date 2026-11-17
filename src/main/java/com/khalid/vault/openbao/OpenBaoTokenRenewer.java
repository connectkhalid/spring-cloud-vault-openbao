package com.khalid.vault.openbao;

import com.khalid.vault.config.VaultServiceProperties;
import com.khalid.vault.admin.IntegrationIdentityService;
import com.khalid.vault.iam.AppIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class OpenBaoTokenRenewer {
    private static final Logger logger = LoggerFactory.getLogger(OpenBaoTokenRenewer.class);
    private final VaultServiceProperties properties;
    private final OpenBaoClient openBao;
    private final IntegrationIdentityService integrationIdentities;

    public OpenBaoTokenRenewer(VaultServiceProperties properties, OpenBaoClient openBao,
                               IntegrationIdentityService integrationIdentities) {
        this.properties = properties;
        this.openBao = openBao;
        this.integrationIdentities = integrationIdentities;
    }

    @Scheduled(fixedDelay = 3_600_000L, initialDelay = 3_600_000L)
    public void renewAppTokens() {
        properties.getIam().getApps().forEach((appId, registration) -> {
            try {
                openBao.renewToken(new AppIdentity(appId, registration));
            } catch (Exception exception) {
                logger.warn("Could not renew OpenBao token for app {}. Check token validity and namespace policy.", appId);
            }
        });
        try {
            integrationIdentities.renewTokens();
        } catch (Exception exception) {
            logger.warn("Could not enumerate managed integration tokens. Check the identity registry policy.");
        }
    }
}
