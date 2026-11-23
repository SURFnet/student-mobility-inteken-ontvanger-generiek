ALTER TABLE custom_agreement_details ALTER COLUMN gastinstelling_deadline TYPE DATE USING (gastinstelling_deadline::date);
