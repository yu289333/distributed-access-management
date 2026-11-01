CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'XOR', 'NOT');

create table policy (
    id  serial primary key,
    parent integer default null references policy(id),
    name text,
    display_name text,
    comment text,
    provider text,
    provider_detail text,
    operator setOperator not null default 'AND',
    condition_raw text,
    condition_cel text,
    condition_json jsonb[]
);
