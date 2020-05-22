FROM identicum/centos-java-maven as build-env
WORKDIR /workspace/demoapp
ADD app ./app
ADD core ./core
COPY pom.xml .
RUN mvn install -DskipTests

# ############################################################################
# Build runtime image
FROM tomcat:8-jdk11-openjdk-slim
LABEL maintainer="Gustavo J Gallardo <ggallard@identicum.com>"

COPY --from=build-env /workspace/demoapp/app/target/oidc-demoapp-c2id.war ./webapps/ROOT.war
RUN apt-get update && \
	apt-get install -y curl
HEALTHCHECK --timeout=5s CMD curl --fail http://localhost:8080/ || exit 1
