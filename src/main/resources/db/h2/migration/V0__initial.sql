CREATE TABLE enrollment_requests
(
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identifier    VARCHAR(255) NOT NULL,
    person_uri    VARCHAR(255) NOT NULL,
    results_uri   VARCHAR(255) NOT NULL,
    person_id     VARCHAR(255),
    access_token  MEDIUMTEXT,
    refresh_token MEDIUMTEXT,
    scope         MEDIUMTEXT   NOT NULL,
    created       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);