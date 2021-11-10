CREATE TABLE enrollment_requests
(
    id            BIGSERIAL PRIMARY KEY,
    identifier    VARCHAR(254) NOT NULL,
    person_uri    VARCHAR(255) NOT NULL,
    results_uri   VARCHAR(255) NOT NULL,
    person_id     VARCHAR(255),
    access_token  TEXT,
    refresh_token TEXT,
    scope         TEXT   NOT NULL,
    created       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);