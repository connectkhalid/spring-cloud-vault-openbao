package com.khalid.vault.dto.admin;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntegrationIdentityResponse(String id, String namespace, Set<String> policies,
                                          boolean enabled, String clientSecret) { }
