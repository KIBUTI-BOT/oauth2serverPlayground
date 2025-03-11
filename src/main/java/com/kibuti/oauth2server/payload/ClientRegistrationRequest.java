package com.kibuti.oauth2server.payload;

import java.util.HashSet;
import java.util.Set;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequest {

    @NotBlank(message = "Application name is required")
    @Size(min = 3, max = 100, message = "Application name must be between 3 and 100 characters")
    private String clientName;

    @NotBlank(message = "Application description is required")
    @Size(max = 1000, message = "Description must be less than 1000 characters")
    private String description;

    @NotEmpty(message = "At least one redirect URI is required")
    private Set<String> redirectUris = new HashSet<>();

    @NotEmpty(message = "At least one scope is required")
    private Set<String> scopes = new HashSet<>();

    private String logoUrl;

    private String homepageUrl;

    private String privacyPolicyUrl;

    private String termsOfServiceUrl;

    private boolean publicClient = false;
}

