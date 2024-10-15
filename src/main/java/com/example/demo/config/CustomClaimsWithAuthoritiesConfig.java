package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class CustomClaimsWithAuthoritiesConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (context.getTokenType().getValue().equals("access_token")) {
                var clientId = context.getRegisteredClient().getClientId();
                var requestedScopes = context.getAuthorizedScopes();

                List<String> scopes;
                if (requestedScopes.isEmpty()) {
                    // If no scopes were requested, use all client scopes
                    scopes = new ArrayList<>(context.getRegisteredClient().getScopes());
                } else {
                    // Use the requested scopes
                    scopes = new ArrayList<>(requestedScopes);
                }

                // Add scopes as an array
                context.getClaims().claim("scope", scopes);
            }
        };
    }

}


