package com.kibuti.oauth2server.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientDetailsResponse {

    private String clientId;
    private String clientName;
    private String clientSecret;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean approved;
}
