package com.kibuti.oauth2server.service;

import java.util.*;

import com.kibuti.oauth2server.entity.RegisteredClientEntity;
import com.kibuti.oauth2server.entity.User;
import com.kibuti.oauth2server.payload.ClientRegistrationRequest;
import com.kibuti.oauth2server.repository.RegisteredClientEntityRepository;
import com.kibuti.oauth2server.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientRegistrationService implements RegisteredClientRepository {

    private final RegisteredClientEntityRepository clientRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toObject)
                .orElse(null);
    }

//    @Transactional
//    public RegisteredClientEntity registerNewClient(ClientRegistrationRequest request, String username) {
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new IllegalArgumentException("User not found"));
//
//        RegisteredClientEntity client = createNewClientEntity(request.getClientName(), user);
//
//        // Set OAuth2 specific attributes
//        client.setClientAuthenticationMethods(Set.of(
//                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()
//        ));
//
//        client.setAuthorizationGrantTypes(Set.of(
//                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
//                AuthorizationGrantType.REFRESH_TOKEN.getValue()
//        ));
//
//        client.setRedirectUris(Set.copyOf(request.getRedirectUris()));
//        client.setScopes(Set.copyOf(request.getScopes()));
//
//        // Client settings with PKCE if needed
//        ClientSettings clientSettings = ClientSettings.builder()
//                .requireAuthorizationConsent(true)
//                .requireProofKey(request.isPublicClient())
//                .build();
//
//        try {
//            client.setClientSettings(objectMapper.writeValueAsString(clientSettings));
//        } catch (JsonProcessingException e) {
//            throw new RuntimeException("Error serializing client settings", e);
//        }
//
//        // Token settings
//        TokenSettings tokenSettings = TokenSettings.builder()
//                .accessTokenTimeToLive(Duration.ofMinutes(30))
//                .refreshTokenTimeToLive(Duration.ofDays(30))
//                .reuseRefreshTokens(false)
//                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
//                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
//                .build();
//
//        try {
//            client.setTokenSettings(objectMapper.writeValueAsString(tokenSettings));
//        } catch (JsonProcessingException e) {
//            throw new RuntimeException("Error serializing token settings", e);
//        }
//
//        return clientRepository.save(client);
//    }



    @Transactional
    public RegisteredClientEntity registerNewClient(ClientRegistrationRequest request, String username, String plainSecret) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        RegisteredClientEntity client = createNewClientEntity(request.getClientName(), user);

        // Set OAuth2 specific attributes
        client.setClientAuthenticationMethods(Set.of(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()
        ));

        client.setAuthorizationGrantTypes(Set.of(
                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                AuthorizationGrantType.REFRESH_TOKEN.getValue()
        ));

        client.setRedirectUris(Set.copyOf(request.getRedirectUris()));
        client.setScopes(Set.copyOf(request.getScopes()));

        // Add these lines to map additional fields from request to entity
        client.setDescription(request.getDescription());
        client.setHomepageUrl(request.getHomepageUrl());
        client.setPrivacyPolicyUrl(request.getPrivacyPolicyUrl());
        client.setTermsOfServiceUrl(request.getTermsOfServiceUrl());
        client.setPublicClient(request.isPublicClient());
        client.setClientSecret(passwordEncoder.encode(plainSecret));

        // Client settings with PKCE if needed
        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(request.isPublicClient())
                .build();

        try {
            client.setClientSettings(objectMapper.writeValueAsString(clientSettings));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing client settings", e);
        }

        // Token settings
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(false)
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        try {
            client.setTokenSettings(objectMapper.writeValueAsString(tokenSettings));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing token settings", e);
        }

        return clientRepository.save(client);
    }


    @Transactional(readOnly = true)
    public List<RegisteredClientEntity> getClientsByUser(String username) {
        return clientRepository.findByOwnerUsername(username);
    }

    @Transactional
    public boolean regenerateClientSecret(String clientId, String username, String newPlainSecret) {
        Optional<RegisteredClientEntity> optionalClient = clientRepository.findByClientIdAndOwnerUsername(clientId, username);

        if (optionalClient.isPresent()) {
            RegisteredClientEntity client = optionalClient.get();
            client.setClientSecret(passwordEncoder.encode(newPlainSecret));
            clientRepository.save(client);
            return true;
        }

        return false;
    }

    @Transactional
    public boolean deleteClient(String clientId, String username) {
        Optional<RegisteredClientEntity> client = clientRepository.findByClientIdAndOwnerUsername(clientId, username);

        if (client.isPresent()) {
            clientRepository.delete(client.get());
            return true;
        }
        return false;
    }

    // Helper method to create a new client entity
    private RegisteredClientEntity createNewClientEntity(String clientName, User owner) {
        RegisteredClientEntity entity = new RegisteredClientEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setClientId(UUID.randomUUID().toString());
        entity.setClientIdIssuedAt(Instant.now());
        entity.setClientSecret(passwordEncoder.encode(generateSecureSecret()));
        entity.setClientName(clientName);
        entity.setOwner(owner);
        entity.setApproved(false);
        return entity;
    }

    // Convert RegisteredClientEntity to Spring Security's RegisteredClient
    private RegisteredClient toObject(RegisteredClientEntity entity) {
        Set<String> clientAuthMethods = entity.getClientAuthenticationMethods();
        Set<String> authGrantTypes = entity.getAuthorizationGrantTypes();
        Set<String> redirectUris = entity.getRedirectUris();
        Set<String> scopes = entity.getScopes();

        ClientSettings clientSettings;
        TokenSettings tokenSettings;

        try {
            clientSettings = objectMapper.readValue(entity.getClientSettings(), ClientSettings.class);
        } catch (Exception e) {
            log.error("Error deserializing client settings", e);
            clientSettings = ClientSettings.builder().build();
        }

        try {
            tokenSettings = objectMapper.readValue(entity.getTokenSettings(), TokenSettings.class);
        } catch (Exception e) {
            log.error("Error deserializing token settings", e);
            tokenSettings = TokenSettings.builder().build();
        }

        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientIdIssuedAt(entity.getClientIdIssuedAt())
                .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                .clientName(entity.getClientName());

        // Add client authentication methods
        clientAuthMethods.forEach(method -> {
            if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(method)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(method)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
            } else if (ClientAuthenticationMethod.NONE.getValue().equals(method)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            }
        });

        // Add authorization grant types
        authGrantTypes.forEach(grantType -> {
            if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
                builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
                builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
            } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
                builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            }
        });

        // Add redirect URIs
        redirectUris.forEach(builder::redirectUri);

        // Add scopes
        scopes.forEach(builder::scope);

        return builder
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();
    }

    // Convert Spring Security's RegisteredClient to RegisteredClientEntity
    private RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        RegisteredClientEntity entity = new RegisteredClientEntity();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());

        // Set client authentication methods
        Set<String> clientAuthMethods = new HashSet<>();
        registeredClient.getClientAuthenticationMethods().forEach(method ->
                clientAuthMethods.add(method.getValue()));
        entity.setClientAuthenticationMethods(clientAuthMethods);

        // Set authorization grant types
        Set<String> authGrantTypes = new HashSet<>();
        registeredClient.getAuthorizationGrantTypes().forEach(grantType ->
                authGrantTypes.add(grantType.getValue()));
        entity.setAuthorizationGrantTypes(authGrantTypes);

        // Set redirect URIs
        entity.setRedirectUris(new HashSet<>(registeredClient.getRedirectUris()));

        // Set scopes
        entity.setScopes(new HashSet<>(registeredClient.getScopes()));

        // Serialize client settings
        try {
            entity.setClientSettings(objectMapper.writeValueAsString(registeredClient.getClientSettings()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing client settings", e);
        }

        // Serialize token settings
        try {
            entity.setTokenSettings(objectMapper.writeValueAsString(registeredClient.getTokenSettings()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing token settings", e);
        }

        return entity;
    }

    private String generateSecureSecret() {
        return UUID.randomUUID().toString();
    }
}