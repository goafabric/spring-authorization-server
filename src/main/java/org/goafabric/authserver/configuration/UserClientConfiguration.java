package org.goafabric.authserver.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Configuration
@Slf4j
public class UserClientConfiguration {

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${spring.security.authorisation.base-uri}") String baseEndpoint) {
        //return AuthorizationServerSettings.builder().build();
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

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
                createClient("oauth2-proxy"));
    }

    private static RegisteredClient createClient(String clientId) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}none")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                //allowed redirect uris of your CLIENT, localhost ist forbidden in favour of 127.0.0.1, dns names otherwise work ...
                .redirectUri("http://127.0.0.1:30200/")
                .redirectUri("http://localhost:30200/")
                .redirectUri("http://127.0.0.1:8080/oauth2/callback")
                .redirectUri("http://127.0.0.1:50900/callees/sayMyName")
                .redirectUri("http://127.0.0.1:50900/login/oauth2/code/keycloak")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .build();
        return registeredClient;
    }

    @Bean
    public UserDetailsService userDetailsService(@Value("${spring.security.authorisation.identities:}") String identities) {
        List<UserDetails> userDetails = new ArrayList<>();
        Arrays.asList(identities.split(",")).forEach(identity -> {
            userDetails.add(
                User.withDefaultPasswordEncoder()
                        .username(identity.split(":")[0])
                        .password(identity.split(":")[1])
                        .roles("USER", "standard")
                        .build()
                );
        });
        return new InMemoryUserDetailsManager(userDetails);
    }

}