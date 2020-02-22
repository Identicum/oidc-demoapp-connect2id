
# oidc-demoapp-c2id
OpenID Connect demo app using Connect2id OIDC Java Library.

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
The demo app can run as a Docker container.
Dockerfile and instructions documented [here](docker/)
