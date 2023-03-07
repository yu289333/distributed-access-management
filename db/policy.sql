CREATE TYPE setOperator AS ENUM ('OR', 'AND', 'XOR', 'NOT');

create table policy (
    id  serial primary key,
    parent integer default null references policy(id),
    name text,
    domain text,
    cloud text,
    operator setOperator not null default 'OR',
    conditions jsonb[]
);