package com.khalid.vault.dto.auth;

public record TokenResponse(String accessToken, String tokenType, long expiresIn) { }
