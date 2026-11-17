package com.khalid.vault.dto.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record TokenRoleRequest(@NotBlank String namespace, @NotBlank String name,
                               @NotEmpty Set<@NotBlank String> allowedPolicies,
                               @NotBlank String period, boolean orphan) { }
