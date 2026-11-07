# Distributed Access Management

Do you have IAM policies in both AWS and Azure? Or do you need to convert AWS IAM policies to Azure policies when migrating from AWS to Azure? Working with so many different types of access (authorization) policies has been the way of life. The goal of this project is to create a distributed access management that can be used AWS, Azure, GCP and all other cloud products just like Active Directory being used by all for identity and authentication management. Before achieving the goal, the project works on converting access policies among different systems. 

This project will serve as proof of concept for the patent pending technology - access policy neutral format "Optimized policy data structure for distributed authorization systems." Essentially, all access policy elements are hierachies (trees) of set operations. Each leaf is a condition which defines a set of permissions or denials. For the same access policy, the differences between different formats, e.g. AWS and Azure, are
- the conditions are defined in different namespaces e.g. AWS ARN vs. Azure URN
- the hierachy of set operations is morphed differently.
The patent pending technology is to morph the access policies in AWS format to the neutral format before morphing them to the Azure format.

## Directory structure
- /db directory contains sample policies from AWS, Azure and GCP as well as the Postgresql entity structure of storing policies
- /lambda contains AWS Lambda code in an attempt to load policies into the Postgresql -- it's not working
- /src contains AWS, Azure, and GCP parsers and a shared PostgreSQL policy-tree writer.
- /examples contains standalone JSON policies for use with the parsers.
- /tests contains parser, tree-validation, and persistence regression tests.

## Policy entry modules

The parsers and database writer are separate:

| Module | Public API | Purpose |
| --- | --- | --- |
| `src/awsPolicyEntry.py` | `parse_policy(source, name=None, provider_detail='arn:aws')` | Parse an AWS IAM policy document. |
| `src/azurePolicyEntry.py` | `parse_policy(source, name=None)` | Parse an Azure RBAC role or Azure Policy definition. |
| `src/gcpPolicyEntry.py` | `parse_policy(source, name=None, provider_detail='iam.googleapis.com')` | Parse a GCP IAM policy (bindings, members, roles, conditions). |
| `src/policyTree.py` | `make_node`, `validate_tree`, `insert_policy_tree`, `write_policy_tree` | Construct, validate, and persist any provider's tree. |

The parsers accept a JSON string or Python dictionary and return an independent
dictionary tree. Every node contains the columns `name`, `display_name`,
`comment`, `provider`, `provider_detail`, `operator`, `condition_raw`,
`condition_cel`, and `condition_json`, plus a `children` list. The writer generates
the database `id` and `parent` values. Legacy `cloud`, `domain`, and `conditions`
fields are not part of this format.

`condition_json` is a JSON expression stored as `jsonb`. Grouping nodes have NULL
expressions, and leaves contain provider-specific predicates. `condition_cel`
remains NULL until a CEL translation is supplied. The root's `condition_raw`
preserves the full input, including metadata, scopes, policy language version,
parameters, and effects. Given a string, its original formatting is retained.

`AND`, `OR`, `NOT`, and `XOR` are the available operators. An empty OR represents
the empty permission set (false); an empty AND represents the universal set
(true). NOT has exactly one child. Expressions and children cannot be mixed on
the same node. Validation rejects cycles, shared children, unknown fields,
duplicate JSON keys, and non-JSON values before writing any rows.

### AWS parsing

AWS trees have `provider = 'AWS'` and `provider_detail = 'arn:aws'`. Set the
`provider_detail` keyword to another partition namespace when needed. The parser
accepts a single Statement or an array, plus `Document`, `PolicyDocument`, and
`PolicyVersion.Document` wrappers. Input must be decoded JSON, not a URL-encoded
IAM API response. Identity policies, resource policies, and trust policies are
supported with basic structural validation.

Each statement is an intact JSON expression, retaining Effect, Sid, Action or
NotAction, Resource or NotResource, Principal or NotPrincipal, and Condition.
The tree represents `AND(OR(allows), NOT(OR(explicit denies)))`; policies without
denies use `OR(allows)`. A deny-only policy grants nothing. Statement matching
requires AWS-aware interpretation of the JSON; Effect and Sid are metadata,
not ordinary matching predicates. This is a representation of one policy's
grants, not an effective-permissions evaluator across AWS policies or SCPs.

### Azure parsing

Azure trees have `provider = 'Azure'`. The parser recognizes REST role definitions
with `properties.permissions`, flattened CLI roles with `permissions`, and
PowerShell roles with `Actions`/`NotActions`/`DataActions`/`NotDataActions`.
For RBAC, `provider_detail = 'Microsoft.Authorization/roleDefinitions'`.

Each permissions block is the union of two separate sets:
`actions minus notActions`, and `dataActions minus notDataActions`. Permissions
blocks are unioned. Exclusions apply only inside their block; they are not global
denies and can be granted by another block or role. Each action pattern is a
JSON leaf retaining its control/data-plane field name. Conditional permission
blocks retain their native condition expression as an additional AND predicate.
Assignable scopes describe where a role can be assigned; they are preserved in
the original source, not treated as the scope of an actual role assignment.

Azure Policy definitions use
`provider_detail = 'Microsoft.Authorization/policyDefinitions'`. Their `if`
expression is parsed recursively: allOf becomes AND, anyOf becomes OR, and not
becomes NOT. Other conditions remain native JSON leaves. These trees describe
applicability, not access grants. The complete then/effect/details, parameters,
and other definition fields remain in the root source; effects are not executed.
Locks, ARM deployment templates, initiatives, and assignments are not parsed.

### GCP parsing

GCP trees have `provider = 'GCP'` and
`provider_detail = 'iam.googleapis.com'`; set `provider_detail` to record a
different IAM API namespace. The parser accepts a policy object as returned by
`getIamPolicy`, optionally wrapped in a `policy` field, with a nonempty
`bindings` array.

Bindings are unioned. Each binding is an AND of one `role` leaf, an OR of its
`members` leaves, and, when present, one `IAM condition` leaf. Each binding's
original JSON is preserved in its `condition_raw`; the root's `condition_raw`
preserves the full input, including `version`, `etag`, and `auditConfigs`.

IAM Conditions are kept as native JSON: the CEL `expression` text is stored
unchanged and is not parsed, translated, or written to `condition_cel`, which
remains NULL. Deny policies, principal access boundary policies, and the
contents of `auditConfigs` are not parsed.

### Usage

Install the database dependency and create the schema in a new PostgreSQL database:

```sh
python -m pip install -r requirements.txt
psql -v ON_ERROR_STOP=1 -f db/policy.sql
```

Preview a tree without connecting to a database:

```sh
python src/awsPolicyEntry.py examples/aws-ec2-readonly.json --dry-run
python src/azurePolicyEntry.py examples/azure-classic-vm-role.json --dry-run
python src/azurePolicyEntry.py examples/azure-audit-vm.json --dry-run
python src/gcpPolicyEntry.py examples/gcp-iam-bindings.json --dry-run
```

Remove `--dry-run` to insert the tree. Use `DATABASE_URL` or libpq's PGHOST,
PGPORT, PGDATABASE, PGUSER, and PGPASSWORD environment variables for the connection.
`--name` overrides the policy name. Both `python src/awsPolicyEntry.py ...` and
`python -m src.awsPolicyEntry ...` are supported, likewise for the Azure and GCP
entry modules.

For programmatic use from the project root:

```python
import os
from pathlib import Path
import psycopg2
from src.awsPolicyEntry import parse_policy
from src.policyTree import write_policy_tree

tree = parse_policy(Path('examples/aws-ec2-readonly.json').read_text(), name='EC2 read only')
connection = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
try:
    root_id = write_policy_tree(connection, tree)
finally:
    connection.close()
```

Use `azurePolicyEntry.parse_policy` or `gcpPolicyEntry.parse_policy` with the
same writer for the other providers. The parsers and dry runs work without
psycopg2 installed. Module imports have no printing, network, or database side
effects.

`write_policy_tree` uses one transaction and returns the root row ID. It rolls
back the whole tree on an insertion failure. Use a dedicated connection with
autocommit disabled, since it commits or rolls back that connection's current
transaction. `insert_policy_tree(cursor, tree)` leaves transaction ownership to
the caller. Both accept optional `table` and `schema` arguments, quoted as SQL
identifiers. Each call inserts a new tree; no schema migration or deduplication
is performed.

Run the regression tests:

```sh
python -m unittest discover -s tests -v
```
