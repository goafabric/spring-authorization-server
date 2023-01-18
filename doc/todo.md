# todo

- localhost problem (OAuth2AuthorizationCodeRequestAuthenticationValidator)
- wildcards in host names or properties
- multiple clients via property
- disable client secret
- email address to get proxy working


      OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).authorizationEndpoint(new Customizer<OAuth2AuthorizationEndpointConfigurer>() {
            @Override
            public void customize(OAuth2AuthorizationEndpointConfigurer oAuth2AuthorizationEndpointConfigurer) {
                oAuth2AuthorizationEndpointConfigurer.authenticationProvider(
                        new OAuth2AuthorizationCodeRequestAuthenticationProvider())
            }
        })
