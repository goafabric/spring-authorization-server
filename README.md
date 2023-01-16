# docker compose
go to /src/deploy/docker and do "./stack up" or "./stack up -native"

# run jvm multi image
docker run --pull always --name callee-service --rm -p50900:50900 goafabric/callee-service:3.0.1-SNAPSHOT

# run native image
docker run --pull always --name callee-service-native --rm -p50900:50900 goafabric/callee-service-native:3.0.1-SNAPSHOT -Xmx32m

# run native image arm
docker run --pull always --name callee-service-native-arm64v8 --rm -p50900:50900 goafabric/callee-service-native-arm64v8:3.0.1-SNAPSHOT -Xmx32m

# loki logger
docker run --pull always --name callee-service --rm -p50900:50900 --log-driver=loki --log-opt loki-url="http://host.docker.internal:3100/loki/api/v1/push" goafabric/callee-service:3.0.1-SNAPSHOT

# openid
http://127.0.0.1:8081/oauth2/authorize?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://127.0.0.1:8081/

http://127.0.0.1:8081/oauth2/authorize?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://127.0.0.1:8081/login/oauth2/code/oauth2-proxy

http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&state=state&redirect_uri=http://127.0.0.1:9000/login/oauth2/code/messaging-client-oidc
                                

#
curl -v -s -X POST http://127.0.0.1:8081/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=user1" \
-d "password=user1" \
-d "grant_type=password" \
-d "client_id=oauth2-proxy" \
-d "scope=openid" \
| jq --raw-output '.access_token'