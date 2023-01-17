# docker compose
go to /src/deploy/docker and do "./stack up" or "./stack up -native"

# run jvm multi image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server:1.0.0-SNAPSHOT

# run native image
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native:1.0.0-SNAPSHOT -Xmx32m

# run native image arm
docker run --pull always --name spring-auth-server --rm -p30200:30200 goafabric/spring-auth-server-native-arm64v8:1.0.0-SNAPSHOT -Xmx32m

# endpoint
http://127.0.0.1:30200/oauth2/auth?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://127.0.0.1:30200/

http://localhost:30200/oauth2/auth?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://localhost:30200/

