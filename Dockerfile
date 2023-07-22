FROM ghcr.io/identicum/centos-java-maven as build-env
WORKDIR /workspace/demoapp
ADD app ./app
ADD core ./core
COPY pom.xml .
RUN mvn install -DskipTests

# ############################################################################
# Build runtime image
FROM ghcr.io/identicum/tomcat:latest

COPY --from=build-env /workspace/demoapp/app/target/oidc-demoapp-c2id.war ./webapps/ROOT.war
RUN apt-get update && \
	apt-get install -y curl inetutils-ping
HEALTHCHECK --timeout=5s CMD curl --fail http://localhost:8080/ || exit 1
