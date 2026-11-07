# Open questions before implementing the condition layer

> A short list of things we could not determine from `README.md`,
> `db/policy.sql`, `src/`, `tests/` and the git history. Answers to these are
> what we need before writing a condition translation layer or a
> tree -> policy emitter. No design decisions are proposed here.

`condition_cel` has no contract yet: `README.md:35-36` says it "remains NULL
until a CEL translation is supplied", `validate_tree()` only checks that it is
a string or `None` (`src/policyTree.py:70-73`), and the git history contains
no definition of its syntax or semantics. The questions below are about what
should go into that column and how it relates to the neutral format.

1. **What language is `condition_cel`?** Google CEL (`cel-spec`), the GCP IAM
   Conditions subset, or something else? Is it required by the patent, or an
   implementation choice made when the column was added (2026-11-01)?
2. **What is a leaf expression?** Claim 1 of US 11,669,527 B1 describes an
   expression as defining "a scope, a range, or a condition of an attribute
   value", and describes joining two expressions on the same attribute into
   their common values / range / scope. CEL gives a boolean predicate, where
   that join becomes a satisfiability problem. Should `condition_cel` hold the
   model itself, or be a serialization of a structured attribute-range model?
3. **Who defines the attribute vocabulary?** Is a neutral vocabulary
   (attribute names, types, operators) owned by this repository - covering
   SAP BTP / S/4HANA as well as AWS, Azure and GCP - or is one provider's
   vocabulary the baseline, with GCP IAM Conditions as the first adapter?
4. **What happens to conditions that do not map?** AWS keys such as
   `aws:MultiFactorAuthPresent`, `aws:SecureTransport`, `ForAllValues:*`, and
   Azure ABAC constructs such as `ActionMatches` / `@Environment[...]` have no
   obvious neutral equivalent. Should they stay in `condition_json` with
   `condition_cel` NULL, should the vocabulary be extended, or should they be
   encoded as macros?
5. **Should tree reduction come back?** The patent's "Optimized" claim rests on
   reducing tree depth (merge a parent and child with the same combination
   rule; `allOf` with an empty leaf; `anyOf` with a satisfied leaf) without
   losing meaning. `2c38f8a` removed `reducePolicy()` and keeps trees lossless;
   equivalent REST- and CLI-shaped Azure inputs currently produce different
   trees. Is a canonical form intended, and should equivalence be provable
   (e.g. checked AST / Z3)?
6. **If CEL is used, where do declarations and the AST live?** Should the
   Environment (variables, types, functions) be a versioned code asset with a
   version reference in the database, and should a checked AST be persisted
   alongside `condition_cel` text, or is text + version enough?
7. **What should we build first?** The condition layer, or
   `emit_aws(tree)` / `emit_azure(tree)` for the second half of the morph? And
   is there already a design note, branch, or discussion answering any of
   1-6? A link is enough.

We have made no code, schema, or dependency changes. `main` is untouched.
