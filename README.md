# description

Simple In Memory OIDC compatible server based on spring boot.
Can be configured by simple properties.
Can run in native mode to only consume 30MB of RAM.
Compatible with Oauth2Proxy

# docker compose
go to /src/deploy/docker and do "./stack up" or "./stack up -native"

# run jvm multi image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server:1.0.1-SNAPSHOT

# run native image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native:1.0.1-SNAPSHOT -Xmx32m

# run native image arm
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native-arm64v8:1.0.1-SNAPSHOT -Xmx32m

# example redirect
http://localhost:30200/oauth2/auth?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://localhost:30200/

# example configuration for users & clients, via application.properties / environment variables, user:password

spring.security.authorization.base-uri: "/oauth2"
spring.security.authorization.clients: "oauth2-proxy:none"
spring.security.authorization.users: "user1:user1,user2:user2,user3:user3"

# oauth2-proxy
docker run --name oauth2-proxy --rm -p4180:4180 quay.io/oauth2-proxy/oauth2-proxy:v7.4.0 \
--email-domain='*' --upstream=file:///dev/null --http-address=0.0.0.0:4180 --set-xauthrequest=true --provider=oidc --skip-oidc-discovery=true \
--client-id=oauth2-proxy --client-secret=none --cookie-secret=SvJIUgqBKxOYSxJwFREiOg== --redirect-url=http://localhost:4180/oauth2/callback --login-url=http://localhost:30200/oauth2/auth \
--oidc-issuer-url=http://host.docker.internal:30200 --oidc-jwks-url=http://host.docker.internal:30200/oauth2/certs --redeem-url=http://host.docker.internal:30200/oauth2/token
