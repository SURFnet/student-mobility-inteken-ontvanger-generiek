# Change Log

All notable changes to this project will be documented in this file.

## [0.2.3]

### Changed

Configuration for JWK set timeout and max size

### Config changes

[Extra config in application.yml](https://github.com/SURFnet/student-mobility-inteken-ontvanger-generiek/blob/8e9cb49f4c7e22f5789c4bb8bb988a5b75526f87/src/main/resources/application.yml#L68...L74) for JWT

```yaml
  jwk:
    # The HTTP connect timeout for JWK set retrieval, in millisecond
    connect-timeout: 1500
    # The HTTP read timeout for JWK set retrieval, in milliseconds
    read-timeout: 1500
    # The HTTP entity size limit for JWK set retrieval, in bytes
    size-limit: 153_600
```

## [0.2.2]

### Changed

- Return error messages to broker (instead of whitelabel error pages)
- Do not store the resultsendpoint, but save the homeinstitution and get the
resultendpoint from service-registry when sending the sesult.
- Store the access- and refreshtoken when refreshed
- Return errors from remote results-endpoint to SIS

### Config changes

Use `broker.service_registry_base_url` instead of
`broker.validation_service_registry_endpoint`. This should point to the base
url of the broker

## [0.0.8]

First release
