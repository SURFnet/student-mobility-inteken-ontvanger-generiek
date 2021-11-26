# Change Log

All notable changes to this project will be documented in this file.

## [0.0.9] - Unreleased

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
