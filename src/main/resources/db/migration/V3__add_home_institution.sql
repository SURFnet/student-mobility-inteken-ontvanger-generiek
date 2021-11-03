ALTER TABLE enrollment_requests ADD COLUMN home_institution VARCHAR(255);
ALTER TABLE enrollment_requests ALTER COLUMN results_uri DROP NOT NULL;
