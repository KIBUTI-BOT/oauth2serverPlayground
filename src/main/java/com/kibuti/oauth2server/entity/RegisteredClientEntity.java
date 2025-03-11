package com.kibuti.oauth2server.entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_registered_client")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisteredClientEntity {

    @Id
    private String id;

    @Column(unique = true)
    private String clientId;

    private Instant clientIdIssuedAt;

    private String clientSecret;

    private Instant clientSecretExpiresAt;

    private String clientName;

    private String description; // For application description

    private String homepageUrl; // For homepage URL

    private String privacyPolicyUrl; // For privacy policy URL

    private String termsOfServiceUrl; // For terms of service URL

    private boolean publicClient = false; // For client type (public/confidential)

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_client_authentication_methods",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "authentication_method")
    private Set<String> clientAuthenticationMethods = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_client_authorization_grant_types",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type")
    private Set<String> authorizationGrantTypes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_client_redirect_uris",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private Set<String> redirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_client_scopes",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope")
    private Set<String> scopes = new HashSet<>();

    @Column(length = 4000)
    private String clientSettings;

    @Column(length = 4000)
    private String tokenSettings;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private User owner;

    private boolean approved = false;

}