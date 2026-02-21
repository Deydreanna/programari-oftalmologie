BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('viewer', 'scheduler', 'superadmin');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_log_result') THEN
        CREATE TYPE audit_log_result AS ENUM ('success', 'failure', 'denied');
    END IF;
END $$;

CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legacy_mongo_id CHAR(24) UNIQUE,
    email TEXT NULL,
    phone TEXT NULL,
    password_hash TEXT NOT NULL,
    google_id TEXT NULL,
    display_name TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci_uq
    ON users ((lower(email)))
    WHERE email IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_phone_uq
    ON users (phone)
    WHERE phone IS NOT NULL;

CREATE INDEX IF NOT EXISTS users_role_idx
    ON users (role);

CREATE INDEX IF NOT EXISTS users_created_at_idx
    ON users (created_at DESC);

DROP TRIGGER IF EXISTS set_users_updated_at ON users;
CREATE TRIGGER set_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at_timestamp();

CREATE TABLE IF NOT EXISTS doctors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legacy_mongo_id CHAR(24) UNIQUE,
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    specialty TEXT NOT NULL DEFAULT 'Oftalmologie',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    consultation_duration_minutes INTEGER NOT NULL DEFAULT 20,
    workday_start TIME NOT NULL DEFAULT '09:00',
    workday_end TIME NOT NULL DEFAULT '14:00',
    months_to_show INTEGER NOT NULL DEFAULT 3,
    timezone TEXT NOT NULL DEFAULT 'Europe/Bucharest',
    created_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    updated_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
    CHECK (consultation_duration_minutes BETWEEN 5 AND 120),
    CHECK (months_to_show BETWEEN 1 AND 12),
    CHECK (workday_end > workday_start),
    CHECK (((EXTRACT(EPOCH FROM (workday_end - workday_start)) / 60)::INTEGER) >= consultation_duration_minutes)
);

CREATE UNIQUE INDEX IF NOT EXISTS doctors_slug_uq
    ON doctors (slug);

CREATE INDEX IF NOT EXISTS doctors_active_display_name_idx
    ON doctors (is_active, display_name);

DROP TRIGGER IF EXISTS set_doctors_updated_at ON doctors;
CREATE TRIGGER set_doctors_updated_at
    BEFORE UPDATE ON doctors
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at_timestamp();

CREATE TABLE IF NOT EXISTS doctor_admin_assignments (
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    legacy_doctor_mongo_id CHAR(24) NULL,
    legacy_user_mongo_id CHAR(24) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (doctor_id, user_id)
);

CREATE INDEX IF NOT EXISTS doctor_admin_assignments_user_idx
    ON doctor_admin_assignments (user_id);

CREATE TABLE IF NOT EXISTS doctor_availability_rules (
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    weekday SMALLINT NOT NULL CHECK (weekday BETWEEN 0 AND 6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (doctor_id, weekday)
);

CREATE INDEX IF NOT EXISTS doctor_availability_rules_weekday_idx
    ON doctor_availability_rules (weekday);

CREATE TABLE IF NOT EXISTS doctor_blocked_days (
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    blocked_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (doctor_id, blocked_date)
);

CREATE INDEX IF NOT EXISTS doctor_blocked_days_date_idx
    ON doctor_blocked_days (blocked_date);

CREATE TABLE IF NOT EXISTS appointments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legacy_mongo_id CHAR(24) UNIQUE,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    type TEXT NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL,
    email_sent BOOLEAN NOT NULL DEFAULT FALSE,
    has_diagnosis BOOLEAN NOT NULL DEFAULT FALSE,
    diagnostic_file_key TEXT NULL,
    diagnostic_file_mime TEXT NULL,
    diagnostic_file_size INTEGER NULL CHECK (diagnostic_file_size IS NULL OR diagnostic_file_size BETWEEN 1 AND 5242880),
    diagnostic_uploaded_at TIMESTAMPTZ NULL,
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE RESTRICT,
    doctor_snapshot_name TEXT NOT NULL DEFAULT '',
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (doctor_id, appointment_date, appointment_time)
);

CREATE INDEX IF NOT EXISTS appointments_doctor_date_idx
    ON appointments (doctor_id, appointment_date);

CREATE INDEX IF NOT EXISTS appointments_date_time_idx
    ON appointments (appointment_date, appointment_time);

CREATE INDEX IF NOT EXISTS appointments_user_idx
    ON appointments (user_id);

CREATE INDEX IF NOT EXISTS appointments_created_at_idx
    ON appointments (created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    legacy_mongo_id CHAR(24) UNIQUE,
    actor_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_role TEXT NOT NULL DEFAULT 'anonymous',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    result audit_log_result NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    logged_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_logs_logged_at_idx
    ON audit_logs (logged_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_action_logged_at_idx
    ON audit_logs (action, logged_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_actor_user_idx
    ON audit_logs (actor_user_id, logged_at DESC);

COMMIT;
