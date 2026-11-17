package com.khalid.vault.dto.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record IntegrationIdentityRequest(@NotBlank String namespace,
                                         @NotEmpty Set<@NotBlank String> policies) { }
