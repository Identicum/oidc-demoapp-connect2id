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

    export DISCOVERY_ENDPOINT=https://idp.identicum.com/.well-known/openid-configuration
    export CLIENT_ID=*some_client_id*
    export CLIENT_SECRET=*some_client_secret*
    export REDIRECT_URI=https://demoapp.identicum.com/oidc-demoapp-c2id/oauth/callback
    export SCOPES=openid,profile
    export LOGOUT_REDIRECT_URI=https://demoapp.identicum.com/oidc-demoapp-c2id/logout.jsp
    # this variable allows you to add additional parameters to the redirect to the authorization_endpoint.
    # possible values are: "acr_values=u2f", "acr_values=u2f otp&prompt=login"
    export ADDTL_AUTHORIZE_PARAMS=

    docker run -d \
        -p 8080:8080 \
        -e "JAVA_OPTS=-Doidc_discovery_endpoint=${DISCOVERY_ENDPOINT} -Dclient_id=${CLIENT_ID} -Dclient_secret=${CLIENT_SECRET} -Dredirect_uri=${REDIRECT_URI} -Dscopes=${SCOPES} -Dpost_logout_redirect_uri=${LOGOUT_REDIRECT_URI} -Dauth_request_uri_param=${ADDTL_AUTHORIZE_PARAMS}" \
        identicum/oidc-demoapp-connect2id

#### Or Run the container mounting your custom web.xml

Run the image, binding associated ports, and mounting your custom web.xml:

    docker run  -d \
        -p 8080:8080 \
        -v $(pwd)/web.xml:/usr/local/tomcat/webapps/oidc-demoapp-c2id/WEB-INF/web.xml \
	    identicum/oidc-demoapp-connect2id
