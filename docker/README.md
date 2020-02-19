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

    docker run -d \
	    -p 8080:8080 \
	    -e "JAVA_OPTS=-Dscopes=openid,profile -Dclient_id=client-id -Dclient_secret=client-secret -Doidc_discovery_endpoint=https://openid_provider_base_url/.well-known/openid-configuration -Dredirect_uri=http://demoapp/oidc-demoapp-c2id/oauth/callback" \
        identicum/oidc-demoapp-connect2id

##### Other optional JAVA_OPTS:
***auth_request_uri_param*** e.g.:
- -Dauth_request_uri_param="acr_values=u2f"
- -Dauth_request_uri_param="acr_values=u2f otp&prompt=login"

#### Or Run the container mounting your custom web.xml


Run the image, binding associated ports, and mounting your custom web.xml:

    docker run  -d \
        -p 8080:8080 \
        -v $(pwd)/web.xml:/usr/local/tomcat/webapps/oidc-demoapp-c2id/WEB-INF/web.xml \
	    identicum/oidc-demoapp-connect2id
