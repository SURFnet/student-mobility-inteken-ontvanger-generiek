ALTER TABLE enrollment_requests ADD COLUMN home_institution VARCHAR(255);
ALTER TABLE enrollment_requests DROP COLUMN results_uri;
