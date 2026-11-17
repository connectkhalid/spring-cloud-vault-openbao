package com.khalid.vault.dto.key;

public record RotationRunResponse(String name, boolean policyEnabled, boolean rotated,
                                  String activeKeyId, String status) { }
