# openid
http://127.0.0.1:30200/oauth2/auth?client_id=oauth2-proxy&response_type=code&scope=openid&state=state&redirect_uri=http://127.0.0.1:30200/

http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&state=state&redirect_uri=http://127.0.0.1:9000/login/oauth2/code/messaging-client-oidc
                                

# stuff
curl -v -s -X POST http://127.0.0.1:30200/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Authorization: BASIC YmFzZQ==" \
-d "username=user1" \           
-d "password=user1" \
-d "grant_type=password" \
-d "client_id=oauth2-proxy" \
-d "scope=openid" \
| jq --raw-output '.access_token'

# doc 

https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-invoking-authorization-endpoint-openid-connect
https://developers.onelogin.com/openid-connect

http://localhost:30200/oidc/realms/tenant-0/.well-known/openid-configuration