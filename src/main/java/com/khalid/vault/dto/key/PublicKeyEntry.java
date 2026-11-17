package com.khalid.vault.dto.key;

public record PublicKeyEntry(String keyId, String type, String state, String createdAt, String publicKey) { }
