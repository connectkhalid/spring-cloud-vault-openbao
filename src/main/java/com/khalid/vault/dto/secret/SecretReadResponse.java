package com.khalid.vault.dto.secret;

import java.util.Map;

public record SecretReadResponse(String name, Map<String, Object> data, long version) { }
