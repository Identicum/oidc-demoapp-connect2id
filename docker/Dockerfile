FROM identicum/centos-java-maven as build-env
WORKDIR /workspace/demoapp
RUN git clone https://github.com/Identicum/oidc-demoapp-connect2id.git .
RUN mvn install -DskipTests

# ############################################################################
# Build runtime image
FROM identicum/centos-tomcat:latest
MAINTAINER Gustavo J Gallardo <ggallard@identicum.com>

RUN yum -y install unzip
COPY --from=build-env /workspace/demoapp/app/target/oidc-demoapp-c2id.war /tmp/
RUN unzip -qq /tmp/oidc-demoapp-c2id.war -d /usr/local/tomcat/webapps/oidc-demoapp-c2id && \
  rm -f /tmp/oidc-demoapp-c2id.war && \
  echo "<% response.sendRedirect(\"/oidc-demoapp-c2id/\"); %>" > webapps/ROOT/index.jsp
