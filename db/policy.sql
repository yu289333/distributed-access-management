CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'NOT', 'SUBTRACT');

create table policy (
    id  serial primary key,
    parent integer default null references policy(id),
    name text,
    display_name text,
    comment text,
    provider text,
    provider_detail text,
    "operator_onChildren" setOperator not null default 'AND',
    condition_raw text,
    condition_cel text,
    condition_json jsonb,
    condition_raw_type text,
    effect text,
    child_position integer CHECK (child_position >= 0)
);
