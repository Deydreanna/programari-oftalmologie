BEGIN;

ALTER TABLE appointments
    ADD COLUMN IF NOT EXISTS first_name TEXT NULL,
    ADD COLUMN IF NOT EXISTS last_name TEXT NULL,
    ADD COLUMN IF NOT EXISTS cnp TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_index CHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS phone_index CHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS cnp_index CHAR(64) NULL;

CREATE INDEX IF NOT EXISTS appointments_email_index_idx
    ON appointments (email_index);

CREATE INDEX IF NOT EXISTS appointments_phone_index_idx
    ON appointments (phone_index);

CREATE INDEX IF NOT EXISTS appointments_cnp_index_idx
    ON appointments (cnp_index);

COMMIT;
