-- Upgrade the original schema without rewriting policy IDs or parent links.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'policy'::regclass AND attname = 'operator' AND NOT attisdropped) THEN
        ALTER TABLE policy RENAME COLUMN operator TO "operator_onChildren";
    END IF;

    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'policy'::regclass AND attname = 'condition_origin' AND NOT attisdropped) THEN
        ALTER TABLE policy RENAME COLUMN condition_origin TO condition_raw_type;
    ELSE
        ALTER TABLE policy ADD COLUMN IF NOT EXISTS condition_raw_type text;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'policy'::regclass AND attname = 'effect' AND NOT attisdropped) THEN
        ALTER TABLE policy ADD COLUMN effect text;

        -- AWS statements stored their effect either in one field leaf or in the full statement.
        UPDATE policy AS statement
        SET effect = lower(statement.condition_json ->> 'Effect')
        WHERE statement.provider = 'AWS'
          AND statement.condition_json ?| ARRAY['Action', 'NotAction']
          AND statement.condition_json ->> 'Effect' IN ('Allow', 'Deny');

        UPDATE policy AS statement
        SET effect = lower(field.condition_json ->> 'Effect')
        FROM policy AS field
        WHERE field.parent = statement.id
          AND statement.provider = 'AWS' AND field.provider = 'AWS'
          AND field.condition_json IN ('{"Effect": "Allow"}', '{"Effect": "Deny"}');
    ELSE
        ALTER TABLE policy ALTER COLUMN effect DROP NOT NULL,
                           ALTER COLUMN effect DROP DEFAULT;
    END IF;
END
$$;
