# oidc-demoapp-connect2id
OpenID Connect demo app using Connect2id OIDC Java Library.

## Source
Source code can be found at: https://github.com/Identicum/oidc-demoapp-connect2id

## Usage

### Install

Build `identicum/oidc-demoapp-connect2id` from source:

    docker build -t identicum/oidc-demoapp-connect2id .

### Run the container

#### Run the container with your custom variables as JAVA_OPTS environment variables

Run the image, binding associated ports, and defining your custom variables as environment variables:

    export DISCOVERY_ENDPOINT="https://idp.identicum.com/.well-known/openid-configuration"
    export CLIENT_ID="*some_client_id*"
    # this variable is optional. For public client the app will use Authorization Code Flow with PCKE.
    export CLIENT_SECRET="*some_client_secret*"
    export REDIRECT_URI="https://demoapp.identicum.com/oidc-demoapp-c2id/oauth/callback"
    export SCOPES="openid,profile"
    export LOGOUT_REDIRECT_URI="https://demoapp.identicum.com/oidc-demoapp-c2id/logout.jsp"
    # this variable allows you to add additional parameters to the redirect to the authorization_endpoint.
    # possible values are: "acr_values=u2f", "acr_values=u2f otp&prompt=login"
    export ADDTL_AUTHORIZE_PARAMS=
    # this variable allows you to enable request object. Default value: false.
    export ENABLE_REQUEST_PARAMETER=
    # this variable allows you to specify signing algorithm for request object. 
    # possible values are: none, HS256 (requires 256+ bit secret), HS384 (requires 384+ bit secret), HS512 (requires 512+ bit secret)
    # Default value: none
    export REQUEST_OBJECT_SIGNING_ALG=
    # this variable allows to skip ssl certificate validation
    # Default value: false
    export SKIP_SSL_CERT_VALIDATION=

    docker run -d \
        -p 8080:8080 \
        -e "JAVA_OPTS=-Doidc_discovery_endpoint='${DISCOVERY_ENDPOINT}' -Dclient_id='${CLIENT_ID}' -Dclient_secret='${CLIENT_SECRET}' -Dredirect_uri='${REDIRECT_URI}' -Dscopes='${SCOPES}' -Dpost_logout_redirect_uri='${LOGOUT_REDIRECT_URI}' -Dauth_request_uri_param='${ADDTL_AUTHORIZE_PARAMS}' -Denable_request_parameter='${ENABLE_REQUEST_PARAMETER}' -Drequest_object_signing_alg='${REQUEST_OBJECT_SIGNING_ALG}' -Dskip_ssl_cert_validation='${SKIP_SSL_CERT_VALIDATION}'" \
        identicum/oidc-demoapp-connect2id

#### Or Run the container mounting your custom web.xml

Run the image, binding associated ports, and mounting your custom web.xml:

    docker run  -d \
        -p 8080:8080 \
        -v $(pwd)/web.xml:/usr/local/tomcat/webapps/oidc-demoapp-c2id/WEB-INF/web.xml \
	    identicum/oidc-demoapp-connect2id
