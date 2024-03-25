FROM eclipse-temurin:8-jdk-alpine
RUN apk --update upgrade && apk add openssl openssl-dev ca-certificates libgcc && update-ca-certificates
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
