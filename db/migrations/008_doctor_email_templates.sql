BEGIN;

ALTER TABLE doctors
    ADD COLUMN IF NOT EXISTS email_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS email_from_name TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_reply_to TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_subject_template TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_html_template TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_text_template TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_signature TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_clinic_name_override TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_location_override TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_contact_phone_override TEXT NULL;

COMMIT;
