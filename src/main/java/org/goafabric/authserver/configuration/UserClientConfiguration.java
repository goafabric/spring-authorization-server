package org.goafabric.authserver.configuration;

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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Configuration
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

}