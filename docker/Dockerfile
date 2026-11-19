FROM eclipse-temurin:21-jdk-alpine
RUN apk --update upgrade && apk add openssl openssl-dev ca-certificates libgcc && update-ca-certificates
COPY target/*.jar app.jar
ENTRYPOINT ["java", "-XX:-UseBASE64Intrinsics", "-jar", "/app.jar"]
