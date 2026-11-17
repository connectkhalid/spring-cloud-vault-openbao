package com.khalid.vault.dto.key;

import jakarta.validation.constraints.NotNull;

public record SymmetricKeyRequest(@NotNull Boolean expirationEnabled) { }
