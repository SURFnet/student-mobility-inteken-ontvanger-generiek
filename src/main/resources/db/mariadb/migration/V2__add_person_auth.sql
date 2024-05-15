ALTER TABLE enrollment_requests ADD COLUMN person_auth VARCHAR(255);
UPDATE enrollment_requests set person_auth = 'HEADER';
ALTER TABLE enrollment_requests MODIFY person_auth VARCHAR(255) NOT NULL;
