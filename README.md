# student-mobility-inteken-ontvanger-generiek

[![Build Status](https://github.com/SURFnet/student-mobility-inteken-ontvanger-generiek/actions/workflows/maven.yml/badge.svg)](https://github.com/SURFnet/student-mobility-inteken-ontvanger-generiek/actions/workflows/maven.yml/badge.svg)
[![codecov](https://codecov.io/gh/SURFnet/student-mobility-inteken-ontvanger-generiek/branch/main/graph/badge.svg)](https://codecov.io/gh/SURFnet/student-mobility-inteken-ontvanger-generiek)

Generic part of the institution hosted part of the broker for educational
cross-institution registrations.

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3

Set the JAVA_HOME property for maven (example for macOS):
```
export JAVA_HOME=/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/
```

## [Building and running](#building-and-running)

### [The student-mobility-inteken-ontvanger-generiek-server](#student-mobility-inteken-ontvanger-generiek-server)

This project uses Spring Boot and Maven. To run locally, type:

```bash
mvn spring-boot:run
```

To build and deploy (the latter requires credentials in your maven settings):

`mvn clean deploy`

## Run as docker comtainer

To run this project as a docker container, simply download
[docker-compose.yml](./docker/docker-compose.yml) and
[application.yml](./docker/application.yml) to a location on your machine and
type `docker compose up -d`.

[See here for available container versions](https://github.com/SURFnet/student-mobility-inteken-ontvanger-generiek/pkgs/container/student-mobility-inteken-ontvanger-generiek%2Fintekenontvanger-generiek)
