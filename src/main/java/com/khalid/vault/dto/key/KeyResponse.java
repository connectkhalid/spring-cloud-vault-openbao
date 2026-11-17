package com.khalid.vault.dto.key;

public record KeyResponse(String name, String type, String keyId, String publicKey, String privateKey) { }
