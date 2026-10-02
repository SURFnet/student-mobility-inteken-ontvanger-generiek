CREATE TABLE student_details
(
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    enrollment_request_id   BIGINT       NOT NULL,
    naam                    VARCHAR(255),
    adres                   VARCHAR(255),
    email                   VARCHAR(255),
    telefoon                VARCHAR(255),
    opleiding               VARCHAR(255),
    studentnummer           VARCHAR(255),
    created                 TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_student_details_enrollment_request_id UNIQUE (enrollment_request_id),
    CONSTRAINT fk_student_details_enrollment_request_id FOREIGN KEY (enrollment_request_id) REFERENCES enrollment_requests(id) ON DELETE CASCADE
);
