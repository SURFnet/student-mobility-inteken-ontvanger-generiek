CREATE TABLE enrollment_requests
(
    id            BIGINT(20)   NOT NULL AUTO_INCREMENT,
    identifier    VARCHAR(254) NOT NULL,
    person_uri    VARCHAR(255) NOT NULL,
    person_id     VARCHAR(255),
    offering_id   VARCHAR(255),
    access_token  MEDIUMTEXT,
    refresh_token MEDIUMTEXT,
    scope         MEDIUMTEXT   NOT NULL,
    created       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);