
# oidc-demoapp-c2id
OpenID Connect demo app using [Connect2id OIDC Java Library](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk).

## Getting started
OIDC demo contains two modules: core and app.

Let's start describing them:

*core:* (com.identicum.oidc:oidc-core-c2id)
This folder contains a maven project with Java filters in charge of doing the OpenID Connect Authentication and Logout (RP-Initiated Logout) process.

*app:* (com.identicum.oicd.apps.:oidc-demoapp-c2id)
This folder contains a maven project with a jsp app used to learn how the OIDC process works.

Within the app/src/main/webapp folder contains the following jsp files:

- *index.jsp* Index of the webapp (public)
- *menu/index.jsp* Home of the web app (protected)
- *logout.jsp*  Logout process


## Configure
In order to deploy the demo application, you need to configure a number of parameters in the [web.xml](app/src/main/webapp/WEB-INF/web.xml). Some of those parameters are endpoint URLs of your IdP. Additionally, you need to create your client application in your IdP and configure the client_id and client_secret.

## Build
The build process to compile the source code is based in Apache Maven. To create the war file, go to the folder where you cloned the repository and run:

	$ mvn clean package

## Run
### WAR
To execute in a web container like Tomcat, simply copy the file to the webapps folder or deploy to your application server following standard procedures.

### Docker
The demo app can run as a Docker container, with your custom variables as JAVA_OPTS environment variables

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
        -e "JAVA_OPTS=-Doidc.discovery_endpoint='${DISCOVERY_ENDPOINT}' -Doidc.client_id='${CLIENT_ID}' -Doidc.client_secret='${CLIENT_SECRET}' -Doidc.redirect_uri='${REDIRECT_URI}' -Doidc.scopes='${SCOPES}' -Doidc.post_logout_redirect_uri='${LOGOUT_REDIRECT_URI}' -Doidc.auth_request_uri_param='${ADDTL_AUTHORIZE_PARAMS}' -Doidc.enable_request_parameter='${ENABLE_REQUEST_PARAMETER}' -Doidc.request_object_signing_alg='${REQUEST_OBJECT_SIGNING_ALG}' -Doidc.skip_ssl_cert_validation='${SKIP_SSL_CERT_VALIDATION}'" \
        identicum/oidc-demoapp-connect2id
