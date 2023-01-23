# description

Simple In Memory OIDC compatible server based on spring boot.
Can be configured by simple properties.
Can run in native mode to only consume 30MB of RAM.
Compatible with Oauth2Proxy

# docker compose
go to /src/deploy/docker and do "./stack up" or "./stack up -native"

# run jvm multi image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server:1.0.2

# run native image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native:1.0.2 -Xmx32m

# run native image arm
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native-arm64v8:1.0.2 -Xmx32m

# example redirect
http://localhost:30200/oidc/auth?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://localhost:30200/

# example configuration for users & clients, via application.properties / environment variables, user:password

spring.security.authorization.base-uri: "/oauth2"
spring.security.authorization.clients: "oauth2-proxy:none"
spring.security.authorization.users: "user1:user1,user2:user2,user3:user3"