package com.khalid.vault.dto.secret;

import jakarta.validation.constraints.NotEmpty;
import java.util.Map;

public record SecretWriteRequest(@NotEmpty Map<String, Object> data) { }
