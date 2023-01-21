package org.goafabric.authserver.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@Slf4j
public class UserClientConfiguration {

    @Bean
    public RegisteredClientRepository registeredClientRepository(@Value("${spring.security.authorization.clients}") String clients) {
        final List<RegisteredClient> clientRegistrations = new ArrayList<>();
        Arrays.asList(clients.split(",")).forEach(client ->
                clientRegistrations.add(createClient(client.split(":")[0], client.split(":")[1])));

        return new InMemoryRegisteredClientRepository(clientRegistrations);
    }

    private static RegisteredClient createClient(String clientId, String secret) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}" + secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("*")
                //.redirectUri("http://127.0.0.1:30200/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .build();
        return registeredClient;
    }

    @Bean
    public UserDetailsService userDetailsService(@Value("${spring.security.authorization.users}") String users) {
        List<UserDetails> userDetails = new ArrayList<>();
        Arrays.asList(users.split(",")).forEach(user -> {
            userDetails.add(
                User.withDefaultPasswordEncoder()
                        .username(user.split(":")[0])
                        .password(user.split(":")[1])
                        .roles("standard")
                        .build()
                );
        });
        return new InMemoryUserDetailsManager(userDetails);
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