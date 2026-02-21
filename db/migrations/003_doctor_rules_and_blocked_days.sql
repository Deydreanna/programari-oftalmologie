BEGIN;

UPDATE doctors
SET legacy_mongo_id = encode(gen_random_bytes(12), 'hex')
WHERE legacy_mongo_id IS NULL;

UPDATE doctor_admin_assignments daa
SET legacy_doctor_mongo_id = d.legacy_mongo_id
FROM doctors d
WHERE daa.doctor_id = d.id
  AND daa.legacy_doctor_mongo_id IS NULL
  AND d.legacy_mongo_id IS NOT NULL;

ALTER TABLE doctor_availability_rules
    ADD COLUMN IF NOT EXISTS start_time TIME NOT NULL DEFAULT '09:00',
    ADD COLUMN IF NOT EXISTS end_time TIME NOT NULL DEFAULT '14:00',
    ADD COLUMN IF NOT EXISTS slot_minutes INTEGER NOT NULL DEFAULT 20,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS effective_from DATE NULL,
    ADD COLUMN IF NOT EXISTS effective_to DATE NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE doctor_availability_rules
    DROP CONSTRAINT IF EXISTS doctor_availability_rules_slot_minutes_chk;

ALTER TABLE doctor_availability_rules
    ADD CONSTRAINT doctor_availability_rules_slot_minutes_chk
    CHECK (slot_minutes BETWEEN 5 AND 120);

ALTER TABLE doctor_availability_rules
    DROP CONSTRAINT IF EXISTS doctor_availability_rules_time_window_chk;

ALTER TABLE doctor_availability_rules
    ADD CONSTRAINT doctor_availability_rules_time_window_chk
    CHECK (end_time > start_time);

ALTER TABLE doctor_availability_rules
    DROP CONSTRAINT IF EXISTS doctor_availability_rules_effective_range_chk;

ALTER TABLE doctor_availability_rules
    ADD CONSTRAINT doctor_availability_rules_effective_range_chk
    CHECK (
        effective_from IS NULL
        OR effective_to IS NULL
        OR effective_to >= effective_from
    );

ALTER TABLE doctor_availability_rules
    DROP CONSTRAINT IF EXISTS doctor_availability_rules_slot_fits_window_chk;

ALTER TABLE doctor_availability_rules
    ADD CONSTRAINT doctor_availability_rules_slot_fits_window_chk
    CHECK (((EXTRACT(EPOCH FROM (end_time - start_time)) / 60)::INTEGER) >= slot_minutes);

CREATE INDEX IF NOT EXISTS doctor_availability_rules_doctor_weekday_active_idx
    ON doctor_availability_rules (doctor_id, weekday, is_active);

DROP TRIGGER IF EXISTS set_doctor_availability_rules_updated_at ON doctor_availability_rules;
CREATE TRIGGER set_doctor_availability_rules_updated_at
    BEFORE UPDATE ON doctor_availability_rules
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at_timestamp();

ALTER TABLE doctor_blocked_days
    ADD COLUMN IF NOT EXISTS reason TEXT NULL,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS created_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS updated_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS disabled_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE doctor_blocked_days
    DROP CONSTRAINT IF EXISTS doctor_blocked_days_disabled_state_chk;

ALTER TABLE doctor_blocked_days
    ADD CONSTRAINT doctor_blocked_days_disabled_state_chk
    CHECK (
        (is_active = TRUE AND disabled_at IS NULL AND disabled_by_user_id IS NULL)
        OR is_active = FALSE
    );

CREATE INDEX IF NOT EXISTS doctor_blocked_days_doctor_date_active_idx
    ON doctor_blocked_days (doctor_id, blocked_date, is_active);

CREATE INDEX IF NOT EXISTS doctor_blocked_days_active_only_idx
    ON doctor_blocked_days (doctor_id, blocked_date)
    WHERE is_active = TRUE;

DROP TRIGGER IF EXISTS set_doctor_blocked_days_updated_at ON doctor_blocked_days;
CREATE TRIGGER set_doctor_blocked_days_updated_at
    BEFORE UPDATE ON doctor_blocked_days
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at_timestamp();

COMMIT;
