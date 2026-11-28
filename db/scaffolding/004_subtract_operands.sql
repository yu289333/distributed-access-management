DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_enum
               WHERE enumtypid = 'setOperator'::regtype AND enumlabel = 'SUBSTRACT') THEN
        ALTER TYPE setOperator RENAME VALUE 'SUBSTRACT' TO 'SUBTRACT';
    ELSE
        ALTER TYPE setOperator ADD VALUE IF NOT EXISTS 'SUBTRACT';
    END IF;
END
$$;

ALTER TABLE policy ADD COLUMN IF NOT EXISTS child_position integer
    CHECK (child_position >= 0);
