CREATE TABLE student_details
(
    id                      BIGINT PRIMARY KEY AUTO_INCREMENT,
    enrollment_request_id   BIGINT       NOT NULL,
    naam                    VARCHAR(254),
    adres                   VARCHAR(254),
    email                   VARCHAR(254),
    telefoon                VARCHAR(254),
    opleiding               VARCHAR(254),
    studentnummer           VARCHAR(254),
    created                 TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_student_details_enrollment_request_id UNIQUE (enrollment_request_id),
    CONSTRAINT fk_student_details_enrollment_request_id FOREIGN KEY (enrollment_request_id) REFERENCES enrollment_requests(id) ON DELETE CASCADE
);
