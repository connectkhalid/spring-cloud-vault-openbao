package com.khalid.vault.dto.key;

import java.time.Instant;

public record SymmetricKeyResponse(String alias, String algorithm, String keyId, String key,
                                   boolean expirationEnabled, Instant refreshAt, Instant expiresAt) { }
