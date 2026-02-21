BEGIN;

ALTER TABLE doctor_admin_assignments
    DROP CONSTRAINT IF EXISTS doctor_admin_assignments_pkey;

ALTER TABLE doctor_admin_assignments
    ALTER COLUMN doctor_id DROP NOT NULL;

ALTER TABLE doctor_admin_assignments
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

UPDATE doctor_admin_assignments
SET id = gen_random_uuid()
WHERE id IS NULL;

ALTER TABLE doctor_admin_assignments
    ALTER COLUMN id SET NOT NULL;

ALTER TABLE doctor_admin_assignments
    ADD CONSTRAINT doctor_admin_assignments_pkey PRIMARY KEY (id);

ALTER TABLE doctor_admin_assignments
    DROP CONSTRAINT IF EXISTS doctor_admin_assignments_doctor_presence_chk;

ALTER TABLE doctor_admin_assignments
    ADD CONSTRAINT doctor_admin_assignments_doctor_presence_chk
    CHECK (doctor_id IS NOT NULL OR legacy_doctor_mongo_id IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS doctor_admin_assignments_doctor_user_uq
    ON doctor_admin_assignments (doctor_id, user_id)
    WHERE doctor_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS doctor_admin_assignments_legacy_doctor_user_uq
    ON doctor_admin_assignments (legacy_doctor_mongo_id, user_id)
    WHERE legacy_doctor_mongo_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS doctor_admin_assignments_legacy_user_idx
    ON doctor_admin_assignments (legacy_user_mongo_id);

CREATE INDEX IF NOT EXISTS doctor_admin_assignments_legacy_doctor_idx
    ON doctor_admin_assignments (legacy_doctor_mongo_id);

COMMIT;
