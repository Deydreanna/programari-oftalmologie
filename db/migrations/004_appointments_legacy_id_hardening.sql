BEGIN;

UPDATE appointments
SET legacy_mongo_id = encode(gen_random_bytes(12), 'hex')
WHERE legacy_mongo_id IS NULL;

ALTER TABLE appointments
    ALTER COLUMN legacy_mongo_id SET DEFAULT encode(gen_random_bytes(12), 'hex');

ALTER TABLE appointments
    ALTER COLUMN legacy_mongo_id SET NOT NULL;

COMMIT;
