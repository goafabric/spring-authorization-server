package org.goafabric.authserver.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Configuration
public class CustomizerConfiguration {
    public static Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
        return (authenticationProviders) ->
                authenticationProviders.forEach((authenticationProvider) -> {
                    if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
                        Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
                                // Override default redirect_uri validator
                                new CustomizerConfiguration.RelaxedRedirectUriValidator()
                                        // Reuse default scope validator
                                        .andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);

                        ((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider)
                                .setAuthenticationValidator(authenticationValidator);
                    }
                });
    }

    //Custom Validator that allows for wildcards and also localhost, in contrast of the standard one that strictly only allows complete uris and NO localhost
    static class RelaxedRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

        @Override
        public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                    authenticationContext.getAuthentication();
            RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
            String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

            if (registeredClient.getRedirectUris().contains("*")) {
                return;
            }

            // Use exact string matching when comparing client redirect URIs against pre-registered URIs
            if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
        }
    }

    //add attributes like emails, and username to jwt for oauthproxy to work correctly, spring will not take care of that on its own
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {

        return context -> {
            final Authentication principal = context.getPrincipal();
            final Set<String> authorities = principal.getAuthorities().stream()
                    .map(authority -> authority.getAuthority().replaceAll("ROLE_", "")).collect(Collectors.toSet());
            context.getClaims().claim("roles", authorities);
            context.getClaims().claim("email", principal.getName() + "@example.org");
            context.getClaims().claim("preferred_username", principal.getName());
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${spring.security.authorization.base-uri}") String baseEndpoint) {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint(baseEndpoint + "/auth")
                .tokenEndpoint(baseEndpoint + "/token")
                .jwkSetEndpoint(baseEndpoint + "/certs")
                .tokenRevocationEndpoint(baseEndpoint + "/revoke")
                .tokenIntrospectionEndpoint(baseEndpoint + "/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint(baseEndpoint + "/userinfo")
                .build();
    }

}
