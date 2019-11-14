FROM identicum/centos-java-maven as build
WORKDIR /workspace/demoapp
RUN git clone https://github.com/Identicum/oidc-demoapp-connect2id.git .
RUN mvn install -DskipTests

FROM tomcat:9.0-jre8-alpine
RUN rm -rf /usr/local/tomcat/webapps/docs/ && \
    rm -rf /usr/local/tomcat/webapps/examples/ && \
    rm -rf /usr/local/tomcat/webapps/manager/

RUN apk update && apk upgrade && apk add zip
COPY --from=build /workspace/demoapp/app/target/oidc-demoapp-c2id.war /tmp
RUN unzip -qq /tmp/oidc-demoapp-c2id.war -d /usr/local/tomcat/webapps/oidc-demoapp-c2id && \
    rm -f /tmp/oidc-demoapp-c2id.war