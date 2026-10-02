CREATE TABLE associations
(
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    association_id          VARCHAR(255) NOT NULL,
    enrollment_request_id   BIGINT   NOT NULL,
    created                 TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_enrollment_request_id FOREIGN KEY (enrollment_request_id) REFERENCES enrollment_requests(id) ON DELETE CASCADE
);

