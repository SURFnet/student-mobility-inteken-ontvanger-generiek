# Change Log

All notable changes to this project will be documented in this file.

## [0.3.0]

- Upgrade to JAVA 21

## [0.2.20]

- Add prompt=consent when requesting offline_access

## [0.2.19]

- Allow using without eduID
- Add GET /assiciations/{personID}

## [0.2.17]

- BREAKING: When using the default file-base database, this update will require the removal of the H2 database as the new version is incompatible with the old data format.
- Feature toggle not to requre an eduID, `require_eduid`

## [0.2.16]

- Added support for EC JWT signing
- extra logging for access tokens

## [0.2.5]

### Changed

- Do not save associationID if enrollment is denied

## [0.2.3]

### Changed

- Configuration for JWK set timeout and max size
- Configure connection pool settings for long waits
- Improve handling database connections under load

### Config changes

[Extra config in application.yml](https://github.com/SURFnet/student-mobility-inteken-ontvanger-generiek/blob/8e9cb49f4c7e22f5789c4bb8bb988a5b75526f87/src/main/resources/application.yml#L68...L74) for JWK set JWK set retrieval

```yaml
  jwk:
    # The HTTP connect timeout for JWK set retrieval, in millisecond
    connect-timeout: 1500
    # The HTTP read timeout for JWK set retrieval, in milliseconds
    read-timeout: 1500
    # The HTTP entity size limit for JWK set retrieval, in bytes
    size-limit: 153_600
```

Extra config in application.yml for connections to backend

```yaml
config:
  connection_timeout_millis: 20_000
  connection_pool_keep_alive_duration_millis: 300_000
  # Set to 0 to disable connection-pooling. If responses are slow, connection-pooling does not matter anyway
  connection_pool_max_idle_connections: 256
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
