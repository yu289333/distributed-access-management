# Distributed Access Management

Do you have IAM policies in both AWS and Azure? Or do you need to convert AWS IAM policies to Azure policies when migrating from AWS to Azure? Working with so many different types of access (authorization) policies has been the way of life. The goal of this project is to create a distributed access management that can be used AWS, Azure, GCP and all other cloud products just like Active Directory being used by all for identity and authentication management. Before achieving the goal, the project works on converting access policies among different systems. 

This project will serve as proof of concept for the patent pending technology - access policy neutral format "Optimized policy data structure for distributed authorization systems." Essentially, all access policy elements are hierachies (trees) of set operations. Each leaf is a condition which defines a set of permissions or denials. For the same access policy, the differences between different formats, e.g. AWS and Azure, are
- the conditions are defined in different namespaces e.g. AWS ARN vs. Azure URN
- the hierachy of set operations is morphed differently.
The patent pending technology is to morph the access policies in AWS format to the neutral format before morphing them to the Azure format.

## Directory structure
- /db directory contains sample policies from AWS, Azure and GCP as well as the Postgresql entity structure of storing policies
- /lambda contains AWS Lambda code in an attempt to load policies into the Postgresql -- it's not working
- /src contains AWS, Azure, and GCP parsers, the AWS emitter, and the shared tree writer.
- /examples contains standalone JSON policies for use with the parsers; /examples/sketches holds the non-JSON row diagrams.
- /tests contains parser, tree-validation, and persistence regression tests.

## Policy entry modules

The parsers and database writer are separate:

| Module | Public API | Purpose |
| --- | --- | --- |
| `src/awsPolicyEntry.py` | `parse_policy(source, name=None, provider_detail='arn:aws')` | Parse an AWS IAM policy document. |
| `src/awsPolicyEmitter.py` | `emit_policy(tree)` (alias `emit_aws`) | Rebuild an AWS IAM policy document from an AWS policy tree. |
| `src/azurePolicyEntry.py` | `parse_policy(source, name=None)` | Parse an Azure RBAC role or Azure Policy definition. |
| `src/azurePolicyEmitter.py` | `emit_policy(tree)` (alias `emit_azure`) | Rebuild an Azure role or policy definition from an Azure policy tree. |
| `src/gcpPolicyEmitter.py` | `emit_policy(tree)` (alias `emit_gcp`) | Rebuild a GCP IAM policy from a GCP policy tree. |
| `src/morph.py` | `translate(tree, source='aws', target='azure')`, `register_target` | Decode a source tree into neutral atoms and encode a target. |
| `src/vocabulary.py` | `atom(domain, verb)`, `DOMAINS`, `VERBS` | Provider-independent action atoms. |
| `src/awsVocabulary.py`, `src/azureVocabulary.py` | `read`/`decode`, `encode`/`build` | Per-provider adapters; a new cloud adds one pair. |
| `src/awsToAzure.py` | `translate(tree)`, `translate_tree(tree)` | Backward-compatible AWS → Azure API and CLI. |
| `src/gcpPolicyEntry.py` | `parse_policy(source, name=None, provider_detail='iam.googleapis.com')` | Parse a GCP IAM policy (bindings, members, roles, conditions). |
| `src/policyTree.py` | `make_node`, `validate_tree`, `canonicalize`, `strip_database_ids`, `insert_policy_tree`, `write_policy_tree`, `load_policy_tree` | Construct, validate, reduce, persist, and read back any provider's tree. |

The parsers accept a JSON string or Python dictionary and return an independent
dictionary tree. Every node contains the columns `name`, `display_name`,
`comment`, `provider`, `provider_detail`, `operator`, `condition_raw`,
`condition_cel`, and `condition_json`, plus a `children` list. The writer generates
the database `id` and `parent` values. Legacy `cloud`, `domain`, and `conditions`
fields are not part of this format.

`condition_json` is a JSON expression stored as `jsonb`. Grouping nodes have NULL
expressions, and leaves contain provider-specific predicates. `condition_cel` is populated for supported leaf predicates; grouping nodes keep
NULL. Unsupported syntax retains its JSON/raw source and an explicit conversion
note in `comment`. The root's `condition_raw`
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

Each statement is an AND group with a separate JSON leaf for each field: Effect,
Action or NotAction, Resource or NotResource, Principal or NotPrincipal, and
Condition. Arrays remain intact in their field leaf. Sid labels the statement
group and sets its display_name to `"Sid": "<value>"`; its complete source is retained in that group’s condition_raw. For example,
`examples/aws-ec2-readonly.json` produces 17 nodes: one OR root, four AND
statement groups, and twelve field leaves, following the sketch in
`examples/aws-ec2-readonly-sql.json`. The sketch is not executable JSON or SQL;
IDs are generated by PostgreSQL and relationships use the schema’s `parent`
column. The default root name is Statement and display_name records Version
when present.
The tree represents `AND(OR(allows), NOT(OR(explicit denies)))`; policies without
denies use `OR(allows)`. A deny-only policy grants nothing. Statement matching
requires AWS-aware interpretation of the JSON; Effect and Sid are metadata,
not ordinary matching predicates. This is a representation of one policy's
grants, not an effective-permissions evaluator across AWS policies or SCPs.

### AWS emitting

`awsPolicyEmitter.emit_policy(tree)` (also exported as `emit_aws`) rebuilds an
AWS IAM policy document from a tree produced by `awsPolicyEntry.parse_policy`,
from a canonicalized version of it, or from the same tree read back from the
database. It is the outbound half of the AWS morph; it does not turn Azure or
GCP trees into AWS policies.

Statements are emitted verbatim from each leaf's `condition_json`, so this
round trip needs no `condition_cel` translation and never sets that column.
Every node must have `provider = 'AWS'`, and the tree must have the shape the
AWS parser produces; other shapes are rejected. Canonicalization may collapse a
one-statement allow or deny group to a leaf, which is accepted. `Document`,
`PolicyDocument`, and `PolicyVersion.Document` wrappers are normalised to a
top-level policy, and outer fields such as `Version` and `Id` are recovered from
the root's `condition_raw`. Statement order is restored by exact content, then by
`Sid`, so statements edited in the tree keep their original slot. Without
`condition_raw` the tree order is used (allows before explicit denies).

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
becomes NOT. Other conditions remain native JSON leaves. The root contains both the applicability (`if`) subtree and a `then` subtree.
The latter uses AND groups for its content and nested details, with individual
JSON/raw leaves for effect and each detail field, following
`examples/azure-audit-vm-sql.json`. The complete source, including parameters,
remains on the root. These trees store policy definitions; effects are not
executed, and the `then` metadata must not be evaluated as access predicates.
Azure Policy `if` predicate leaves populate `condition_cel` from their JSON.
Grouping nodes retain NULL CEL; detail metadata receives equality expressions. the effect leaf uses
`effect == "audit"` (or its source value), with a string variable `effect` supplied
to the evaluator. This comparison describes the outcome; it does not execute it. `allOf` maps to AND
and `not` maps to NOT in the tree.
Locks, ARM deployment templates, initiatives, and assignments are not parsed.

### Azure emitting

`azurePolicyEmitter.emit_policy(tree)` (also exported as `emit_azure`) rebuilds
the Azure document from a tree produced by `azurePolicyEntry.parse_policy` or
read back from the database. It is the outbound half of the Azure morph; it does
not turn AWS or GCP trees into Azure policies.

Outer metadata (id, name, roleName or displayName, description, mode, parameters,
assignableScopes) comes from the root's `condition_raw`. The permissions or
`policyRule` are rebuilt from the tree, so edits to leaves are reflected. RBAC
supports the REST (`properties.permissions`), flattened CLI (`permissions`), and
PowerShell (`Actions`/`NotActions`/...) shapes, chosen from the raw document. For
policy definitions, `if` becomes `allOf`/`anyOf`/`not` again and `then` is rebuilt
from the effect and detail leaves.

Every node must have `provider = 'Azure'`, and the tree must have the parser's
shape. Canonicalized Azure trees are not accepted: canonicalization drops the
`permissions` and `then` grouping labels the emitter uses. Locks, ARM templates,
initiatives, and assignments are not emitted.

### Cross-cloud translation (AWS → Azure)

`morph.translate(tree, source='aws', target='azure')` returns an Azure RBAC
role definition and a report; `translate_tree` returns the Azure tree instead, so
the result still flows through the shared format. The AWS tree is read back to a
policy document (so edits to its leaves are reflected), each action is decoded to
a neutral atom, the atom is encoded for the target, and the Azure document is
parsed into an Azure tree that `azurePolicyEmitter.emit_policy` reproduces.

The translation is split into adapters, not one translator per pair:

```
AWS action ──decode──▶ atom {domain, verb} ──encode──▶ Azure action
```

- `awsVocabulary.decode`: `ec2:Describe*` → `{compute, read}`; the service table
  maps `ec2`, `s3`, `logs`, ... to domains and the verb prefix maps to
  `read`/`write`/`delete`/`all`;
- `azureVocabulary.encode`: `{compute, read}` → `Microsoft.Compute/*/read`;
- `morph.translate` is the engine; `register_target()` adds a target adapter.

Adding a provider therefore adds one adapter pair (a source reader/decoder or a
target encoder/builder), not a translator for every ordered pair: adapters grow
with providers (2N) instead of with pairs (N(N−1)). Today only `aws → azure` is
wired.

The report lists unmapped actions, untranslated `Resource` ARNs, and every
approximation. This is a starting point, not a proof of equivalence: the mapping
is service-level, `notActions` is block-scoped (it does not override grants from
other roles), and conditions, `NotAction`/`NotResource`, and principals are not
translated.

```sh
python src/awsToAzure.py examples/aws-ec2-readonly.json --report
python - <<'PY'
from src.awsPolicyEntry import parse_policy
from src.morph import translate
tree = parse_policy(open('examples/aws-ec2-readonly.json').read())
document, report = translate(tree, source='aws', target='azure')
print(document['permissions'][0]['actions'])
PY
```

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

### GCP emitting

`gcpPolicyEmitter.emit_policy(tree)` (also exported as `emit_gcp`) rebuilds the
GCP IAM policy from a tree produced by `gcpPolicyEntry.parse_policy` or read back
from the database. Bindings are rebuilt from the role, members, and optional IAM
condition leaves, so edits are reflected; `version` and `etag` come from the
root's `condition_raw`. Every node must have `provider = 'GCP'`. It is the
outbound half of the GCP morph; it does not turn AWS or Azure trees into GCP
policies.

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

Rebuild an AWS policy from a tree saved by `--dry-run`:

```sh
python src/awsPolicyEntry.py examples/aws-ec2-readonly.json --dry-run > tree.json
python src/awsPolicyEmitter.py tree.json
```

Rebuild an Azure role or policy definition from a saved tree:

```sh
python src/azurePolicyEntry.py examples/azure-classic-vm-role.json --dry-run > tree.json
python src/azurePolicyEmitter.py tree.json
```

Rebuild a GCP policy from a saved tree:

```sh
python src/gcpPolicyEntry.py examples/gcp-iam-bindings.json --dry-run > tree.json
python src/gcpPolicyEmitter.py tree.json
```

### Example policies

| file | covers |
| --- | --- |
| `examples/aws-ec2-readonly.json` | four allow statements |
| `examples/aws-mfa-mandated-policy.json` | allow, explicit deny, and an AWS `Condition` |
| `examples/aws-secrets-readonly.json` | a concrete resource ARN |
| `examples/aws-ec2-full-access-api.json` | the `Document` API-response wrapper |
| `examples/aws-ec2-trust-policy.json` | a trust policy (Principal, no Resource) |
| `examples/azure-audit-vm.json` | a policy definition with `then` details |
| `examples/azure-classic-vm-role.json` | a REST role with assignable scopes |
| `examples/azure-powershell-web-app.json` | the PowerShell `Actions` shape |
| `examples/gcp-iam-bindings.json` | two bindings, one with an IAM condition |

### Round trip each provider

Each pair writes a tree and rebuilds the source document; the comparison is on
parsed JSON, because the emitters reformat:

```sh
python src/awsPolicyEntry.py examples/aws-ec2-readonly.json --dry-run > aws-tree.json
python src/awsPolicyEmitter.py aws-tree.json > aws-out.json
python src/azurePolicyEntry.py examples/azure-audit-vm.json --dry-run > azure-tree.json
python src/azurePolicyEmitter.py azure-tree.json > azure-out.json
python src/gcpPolicyEntry.py examples/gcp-iam-bindings.json --dry-run > gcp-tree.json
python src/gcpPolicyEmitter.py gcp-tree.json > gcp-out.json

python - <<'PY'
import json
pairs = [('examples/aws-ec2-readonly.json', 'aws-out.json'),
         ('examples/azure-audit-vm.json', 'azure-out.json'),
         ('examples/gcp-iam-bindings.json', 'gcp-out.json')]
for source, rebuilt in pairs:
    assert json.load(open(source)) == json.load(open(rebuilt)), rebuilt
print('round trip exact')
PY
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
same writer for the other providers. The AWS emitter is pure Python and needs no
database. The parsers, the emitter, and dry runs work without psycopg2
installed. Module imports have no printing, network, or database side effects.

`write_policy_tree` uses one transaction and returns the root row ID. It rolls
back the whole tree on an insertion failure. Use a dedicated connection with
autocommit disabled, since it commits or rolls back that connection's current
transaction. `insert_policy_tree(cursor, tree)` leaves transaction ownership to
the caller. Both accept optional `table` and `schema` arguments, quoted as SQL
identifiers. Each call inserts a new tree; no schema migration or deduplication
is performed.

`load_policy_tree(cursor, root_id)` reverses the write: one recursive query
fetches the subtree and the rows are reassembled by `parent`. The result is
validated, so a truncated or cyclic subtree raises instead of returning a
partial tree. The caller owns the cursor and the transaction.

`canonicalize(tree)` returns a reduced copy of a validated tree without changing
its meaning. It splices grouping children that repeat their parent's operator,
removes `NOT(NOT x)` and neutral empty groups, and collapses single-child
grouping nodes. Leaf expressions are never touched, so any truth assignment to
the leaves evaluates the same before and after. Labels and per-node
`condition_raw` text of eliminated nodes are dropped; the root keeps its own
`condition_raw`, so an AWS tree still emits. Use the canonical form for
comparison or for the "Optimized" node-count claim, not as a replacement for the
lossless tree.

The two hand-drawn row layouts under `examples/sketches/` are documentation, not
parsed input: they use unquoted keys and nested blocks without keys, so they are
not JSON.

Run the regression tests (CEL runtime is a development dependency):

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```


### Condition source formats and module layout

`provider` and `provider_detail` identify policy language and dialect, not its
serialization. `condition_origin` identifies the input format (`json`, `cel`, or
an explicitly registered future format). No database default guesses JSON for
unknown records. Existing formats must be verified before assigning an origin.

For a condition leaf, populated raw, JSON and expression columns describe the
same source condition. JSON-origin text inputs retain exact input fragments in
`condition_raw`, including whitespace and escaping. A raw fragment can be a JSON
object or an object member such as `"Action" : [ "read", "write" ]`. The matching
`condition_json` is `{"Action": ["read", "write"]}` and `condition_cel` is
`Action == ["read", "write"]`. Conflicting raw/JSON representations are rejected.
The converter preserves the raw source; it does not replace it with generated
JSON or CEL. Python dict inputs have no original lexical text, so raw leaf text
is NULL rather than invented. Their root/group context may use a JSON
serialization of that object. Root raw text continues to retain the complete
input policy; group source is context, not a separate leaf predicate.

Azure array fields stay intact in one leaf so their raw fragments can come from
the input. Older stored trees keep their IDs and structure; transformed leaves
without an exact source fragment retain NULL raw rather than claiming generated
text is original. Their JSON and expressions remain usable.

Fresh databases use `db/policy.sql`. Apply this additive migration to existing
ones (it is safe to repeat):

```sh
psql -v ON_ERROR_STOP=1 -1 -f db/migrations/001_condition_origin.sql
```

Shared modules are separated by responsibility:

| Module | Responsibility |
| --- | --- |
| `policyDocument.py` | Strict JSON document loading |
| `conditionSource.py` | Original text, origin formats, format adapter registration |
| `conditionFormat.py` | Literal/comparison formatting |
| `awsCondition.py`, `azureCondition.py` | Provider-specific condition rendering |
| `conditionExpression.py` | Source-to-expression dispatch and leaf population |
| `policyTree.py` | Nodes and validation |
| `policyStore.py` | Database inserts and transactions |
| `policyExport.py` | Database trees with IDs and parent IDs |
| `policyCli.py` | Shared parser CLI |
| `convertConditions.py` | Convert stored leaf conditions |

The provider entry modules compose these helpers. Existing `policyTree` public
imports and `conditionCel.py` remain compatibility facades. The former
`backfillCel.py` command is a deprecated wrapper around `convertConditions.py`.

```sh
python -m src.convertConditions                 # preview missing conversions
python -m src.convertConditions --apply         # atomic conversion
python -m src.convertConditions --replace       # preview recomputing existing expressions
python -m src.convertConditions --replace --apply
```

Conversion prefers the decoded original source and verifies any JSON alternative
against it. When only JSON is available, it uses that. Successful conversions
also retain normalized JSON and format metadata where known; unsupported formats
or mismatches abort the transaction. `condition_raw` is never rewritten by this
command. New formats use `register_condition_format(name, decoder)` with a decoder
returning the same condition object as the JSON representation. Native CEL raw
text with `condition_origin='cel'` can pass through without inventing JSON. YAML
and other formats are not yet implemented, and never guessed from the provider.

AWS fields and Azure RBAC fields compare their original values, preserving case,
arrays and nested objects. Examples are `Effect == "Allow"`, `Resource == "*"`,
`dataActions == ["Microsoft.AppPlatform/Spring/eurekaService/read"]` and
`assignableScopes == ["/", "/abc"]`. List equality includes item order. No request
variables or wildcard expansion are introduced; these describe source values,
not effective authorization decisions. NOT remains in the tree.

Azure `field`/`equals` preserves the field alias verbatim, for example
`Microsoft.Compute/virtualMachines/storageProfile.osDisk.encryptionSettings.enabled == true`.
As previously requested, aliases containing `/` are readable expressions requiring
an adapter before standard CEL evaluation. Metadata leaves such as effect,
severity, name and message also receive source-preserving comparisons.

Install test dependencies and run checks:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

PostgreSQL integration tests run when DATABASE_URL is set. In the prepared cloud
workspace:

```sh
bash /workspace/.onboarding/start.sh
source /workspace/.onboarding/env.sh
cd /workspace/distributed-access-management
```

To fill missing expressions on existing leaf rows, use
`python -m src.backfillCel` to preview and `python -m src.backfillCel --apply`
to apply atomically. Existing non-NULL expressions are preserved, and unsupported
sources abort the transaction. The cloud workspace must be connected; the
startup helper starts PostgreSQL, not an offline cloud machine.

Assignable scopes are retained together in one leaf directly under the role
root. They use CEL list equality: `assignableScopes == ["/", "/abc"]`.
The evaluator must supply `assignableScopes` as a list. Equality compares the
complete list, including item order; it is not a membership check. An empty list
produces `assignableScopes == []`.

Generated database-tree examples with actual local IDs and parent IDs are saved
in `examples/generated/`. These are illustrative exports; new database imports
generate their own IDs. `tests/test_generated_examples.py` parses the matching
source examples and asserts that the result equals the export after
`strip_database_ids()`, so the samples stay a checked golden reference.

Generated exports are in `examples/generated/`. They include actual local IDs;
fresh imports generate their own IDs. Existing snapshots retain the older tree
structure, while new parses keep complete Azure permission arrays together.
