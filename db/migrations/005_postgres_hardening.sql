BEGIN;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_legacy_mongo_id_format_chk;

ALTER TABLE users
    ADD CONSTRAINT users_legacy_mongo_id_format_chk
    CHECK (legacy_mongo_id IS NULL OR btrim(legacy_mongo_id) ~ '^[A-Fa-f0-9]{24}$');

ALTER TABLE doctors
    DROP CONSTRAINT IF EXISTS doctors_legacy_mongo_id_format_chk;

ALTER TABLE doctors
    ADD CONSTRAINT doctors_legacy_mongo_id_format_chk
    CHECK (legacy_mongo_id IS NULL OR btrim(legacy_mongo_id) ~ '^[A-Fa-f0-9]{24}$');

ALTER TABLE appointments
    DROP CONSTRAINT IF EXISTS appointments_legacy_mongo_id_format_chk;

ALTER TABLE appointments
    ADD CONSTRAINT appointments_legacy_mongo_id_format_chk
    CHECK (legacy_mongo_id IS NULL OR btrim(legacy_mongo_id) ~ '^[A-Fa-f0-9]{24}$');

ALTER TABLE doctor_admin_assignments
    DROP CONSTRAINT IF EXISTS doctor_admin_assignments_legacy_doctor_id_format_chk;

ALTER TABLE doctor_admin_assignments
    ADD CONSTRAINT doctor_admin_assignments_legacy_doctor_id_format_chk
    CHECK (
        legacy_doctor_mongo_id IS NULL
        OR btrim(legacy_doctor_mongo_id) ~ '^[A-Fa-f0-9]{24}$'
    );

ALTER TABLE doctor_admin_assignments
    DROP CONSTRAINT IF EXISTS doctor_admin_assignments_legacy_user_id_format_chk;

ALTER TABLE doctor_admin_assignments
    ADD CONSTRAINT doctor_admin_assignments_legacy_user_id_format_chk
    CHECK (
        legacy_user_mongo_id IS NULL
        OR btrim(legacy_user_mongo_id) ~ '^[A-Fa-f0-9]{24}$'
    );

CREATE INDEX IF NOT EXISTS doctor_admin_assignments_user_created_at_idx
    ON doctor_admin_assignments (user_id, created_at);

COMMIT;
