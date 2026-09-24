# Build the executable JAR
FROM ballerina/ballerina:2201.13.6 AS build
# ballerina/mcp 2.0.0 is not on Ballerina Central yet, so install the vendored bala into the local repository
COPY --chown=ballerina vendor/ballerina /home/ballerina/.ballerina/repositories/local/bala/ballerina
# /home/ballerina is a VOLUME in the base image, and Buildah (used by Choreo) discards files
# that RUN steps write there, so build outside it
USER root
RUN mkdir /app && chown ballerina /app
USER ballerina
WORKDIR /app
COPY --chown=ballerina . .
RUN bal build

# Run it on a plain Java 21 runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/bin/backend.jar backend.jar
# Choreo requires a non-root UID between 10000 and 20000
USER 10014
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "backend.jar"]
