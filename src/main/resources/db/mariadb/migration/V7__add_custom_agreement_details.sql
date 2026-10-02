CREATE TABLE custom_agreement_details
(
    id                      BIGINT PRIMARY KEY AUTO_INCREMENT,
    enrollment_request_id   BIGINT       NOT NULL,
    module_naam             VARCHAR(254),
    module_code             VARCHAR(254),
    onderwijsperiode_start  DATE,
    onderwijsperiode_eind   DATE,
    thuisinstelling_naam    VARCHAR(254),
    gastinstelling_naam     VARCHAR(254),
    created                 TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_custom_agreement_details_enrollment_request_id UNIQUE (enrollment_request_id),
    CONSTRAINT fk_custom_agreement_details_enrollment_request_id FOREIGN KEY (enrollment_request_id) REFERENCES enrollment_requests(id) ON DELETE CASCADE
);
