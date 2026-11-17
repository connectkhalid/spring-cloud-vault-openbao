package com.khalid.vault.dto.admin;

import jakarta.validation.constraints.NotBlank;

public record PolicyRequest(@NotBlank String namespace, @NotBlank String name, @NotBlank String policy) { }
