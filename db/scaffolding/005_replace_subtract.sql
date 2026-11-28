-- Rewrite stored A minus B as AND(A, NOT(B)) before retiring the enum value.
DO $$
DECLARE
    operands record;
    negation_id integer;
BEGIN
    LOCK TABLE policy IN ACCESS EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM pg_enum
                   WHERE enumtypid = 'setOperator'::regtype AND enumlabel = 'SUBTRACT') THEN
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM policy AS operation
        LEFT JOIN policy AS child ON child.parent = operation.id
        WHERE operation."operator_onChildren"::text = 'SUBTRACT'
        GROUP BY operation.id
        HAVING count(child.id) <> 2
            OR count(*) FILTER (WHERE child.child_position = 0) <> 1
            OR count(*) FILTER (WHERE child.child_position = 1) <> 1
    ) THEN
        RAISE EXCEPTION 'Cannot replace SUBTRACT until each node has operands at positions 0 and 1';
    END IF;

    FOR operands IN
        SELECT operation.id, operation.provider, operation.provider_detail, excluded.id AS right_id
        FROM policy AS operation
        JOIN policy AS excluded ON excluded.parent = operation.id AND excluded.child_position = 1
        WHERE operation."operator_onChildren"::text = 'SUBTRACT'
    LOOP
        INSERT INTO policy (parent, name, provider, provider_detail, "operator_onChildren", child_position)
        VALUES (operands.id, 'Exclude', operands.provider, operands.provider_detail, 'NOT', 1)
        RETURNING id INTO negation_id;

        UPDATE policy SET parent = negation_id, child_position = NULL WHERE id = operands.right_id;
        UPDATE policy SET "operator_onChildren" = 'AND' WHERE id = operands.id;
    END LOOP;

    ALTER TYPE setOperator RENAME TO setOperator_with_subtract;
    CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'NOT');
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" DROP DEFAULT;
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" TYPE setOperator
        USING ("operator_onChildren"::text::setOperator);
    ALTER TABLE policy ALTER COLUMN "operator_onChildren" SET DEFAULT 'AND';
    DROP TYPE setOperator_with_subtract;
END
$$;
