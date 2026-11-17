package com.khalid.vault.dto.key;

import jakarta.validation.constraints.Min;

public record RotationPolicyRequest(boolean enabled, @Min(0) long intervalSeconds) { }
