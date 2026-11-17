package com.khalid.vault.dto.admin;

import jakarta.validation.constraints.NotBlank;

public record NamespaceRequest(@NotBlank String name, String parent) { }
