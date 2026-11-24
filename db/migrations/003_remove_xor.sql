-- Run after 002_policy_fields.sql.
DO $$
BEGIN
    LOCK TABLE policy IN ACCESS EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM pg_enum
                   WHERE enumtypid = 'setOperator'::regtype AND enumlabel = 'XOR') THEN
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM policy WHERE "operator_onChildren" = 'XOR') THEN
        RAISE EXCEPTION 'Cannot remove XOR while policy rows still use it';
    END IF;

    ALTER TYPE setOperator RENAME TO setOperator_with_xor;
    CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'NOT');
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" DROP DEFAULT;
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" TYPE setOperator
        USING ("operator_onChildren"::text::setOperator);
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" SET DEFAULT 'AND';
    DROP TYPE setOperator_with_xor;
END
$$;
