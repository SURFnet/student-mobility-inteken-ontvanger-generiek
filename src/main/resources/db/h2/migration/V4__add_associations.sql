CREATE TABLE associations
(
    id                      BIGINT(20)   NOT NULL AUTO_INCREMENT,
    association_id          VARCHAR(254) NOT NULL,
    enrollment_request_id   BIGINT(20)   NOT NULL,
    created                 TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_enrollment_request_id FOREIGN KEY (enrollment_request_id) REFERENCES enrollment_requests(id) ON DELETE CASCADE
);

