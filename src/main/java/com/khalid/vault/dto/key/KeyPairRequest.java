package com.khalid.vault.dto.key;

import jakarta.validation.constraints.NotBlank;

public record KeyPairRequest(@NotBlank String type) { }
