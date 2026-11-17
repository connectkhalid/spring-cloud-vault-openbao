package com.khalid.vault.dto.key;

public record PolicyResponse(String alias, boolean enabled, long intervalSeconds, String lastRotatedAt) { }
