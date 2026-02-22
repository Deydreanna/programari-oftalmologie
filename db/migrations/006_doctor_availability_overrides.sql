BEGIN;

ALTER TABLE doctor_availability_rules
    DROP CONSTRAINT IF EXISTS doctor_availability_rules_pkey;

ALTER TABLE doctor_availability_rules
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

UPDATE doctor_availability_rules
SET id = gen_random_uuid()
WHERE id IS NULL;

ALTER TABLE doctor_availability_rules
    ALTER COLUMN id SET NOT NULL;

ALTER TABLE doctor_availability_rules
    ADD CONSTRAINT doctor_availability_rules_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX IF NOT EXISTS doctor_availability_rules_default_uq
    ON doctor_availability_rules (doctor_id, weekday)
    WHERE effective_from IS NULL
      AND effective_to IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS doctor_availability_rules_single_day_override_uq
    ON doctor_availability_rules (doctor_id, effective_from)
    WHERE effective_from IS NOT NULL
      AND effective_to IS NOT NULL
      AND effective_from = effective_to;

CREATE INDEX IF NOT EXISTS doctor_availability_rules_doctor_effective_idx
    ON doctor_availability_rules (doctor_id, effective_from, effective_to, is_active);

COMMIT;
