# Schema

This document describes the ORM schema defined in `src/reaper/db/models.py`. It is intentionally limited to models, fields, types, nullability, defaults, foreign keys, and table-level constraints so an agent can reason about database updates without reading the ORM source.

## `targets`

Fields:
- `id`: `Integer`, primary key, not null
- `slug`: `String(255)`, not null
- `display_name`: `String(255)`, nullable
- `binary_path`: `Text`, nullable
- `binary_sha256`: `String(64)`, nullable
- `metadata_json`: `JSONB`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- unique: `uq_targets_slug` on `slug`

Relationships:
- one-to-many to `functions`, `annotations`, `call_graph_edges`, `modules`, `data_types`

## `functions`

Fields:
- `id`: `Integer`, primary key, not null
- `target_id`: `Integer`, not null, foreign key to `targets.id`, `ON DELETE CASCADE`
- `address`: `BigInteger`, not null
- `proposed_name`: `String(255)`, nullable
- `original_symbol_name`: `String(255)`, nullable
- `reconstructed_signature`: `Text`, nullable
- `calling_convention`: `String(64)`, nullable
- `decompiled_pseudocode`: `Text`, nullable
- `ai_generated_summary`: `Text`, nullable
- `complexity_score`: `Numeric(10, 4)`, nullable
- `code_embedding`: `Vector(1024)`, nullable
- `summary_embedding`: `Vector(1024)`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- unique: `uq_functions_target_address` on `(target_id, address)`
- unique: `uq_functions_id_target` on `(id, target_id)`

Relationships:
- many-to-one to `targets`
- one-to-many to `call_graph_edges` as caller
- one-to-many to `call_graph_edges` as callee

## `annotations`

Fields:
- `id`: `Integer`, primary key, not null
- `target_id`: `Integer`, not null, foreign key to `targets.id`, `ON DELETE CASCADE`
- `subject_type`: `String(50)`, not null
- `subject_id`: `String(255)`, not null
- `agent_id`: `String(255)`, not null
- `confidence`: `Numeric(3, 2)`, not null
- `version`: `Integer`, not null, server default `1`
- `supersedes_id`: `Integer`, nullable, self-referential foreign key to `annotations.id`, `ON DELETE SET NULL`
- `body`: `Text`, not null
- `payload`: `JSONB`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- check: `ck_annotations_confidence` enforcing `0.0 <= confidence <= 1.0`
- check: `ck_annotations_version` enforcing `version >= 1`

Relationships:
- many-to-one to `targets`
- self-reference through `supersedes` / `superseded_by`

## `call_graph_edges`

Fields:
- `id`: `Integer`, primary key, not null
- `target_id`: `Integer`, not null, foreign key to `targets.id`, `ON DELETE CASCADE`
- `caller_function_id`: `Integer`, not null
- `callee_function_id`: `Integer`, not null
- `call_site_address`: `BigInteger`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- foreign key: `(caller_function_id, target_id)` -> `functions(id, target_id)`, `ON DELETE CASCADE`
- foreign key: `(callee_function_id, target_id)` -> `functions(id, target_id)`, `ON DELETE CASCADE`
- unique: `uq_call_graph_edge_target_site` on `(target_id, caller_function_id, callee_function_id, call_site_address)`

Relationships:
- many-to-one to `targets`
- many-to-one to `functions` as caller
- many-to-one to `functions` as callee

## `modules`

Fields:
- `id`: `Integer`, primary key, not null
- `target_id`: `Integer`, not null, foreign key to `targets.id`, `ON DELETE CASCADE`
- `name`: `String(255)`, not null
- `description`: `Text`, nullable
- `agent_id`: `String(255)`, nullable
- `confidence`: `Numeric(3, 2)`, nullable
- `provenance`: `JSONB`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- unique: `uq_modules_target_name` on `(target_id, name)`
- check: `ck_modules_confidence` enforcing `confidence IS NULL OR (0.0 <= confidence <= 1.0)`

Relationships:
- many-to-one to `targets`

## `data_types`

Fields:
- `id`: `Integer`, primary key, not null
- `target_id`: `Integer`, not null, foreign key to `targets.id`, `ON DELETE CASCADE`
- `name`: `String(255)`, not null
- `kind`: `String(32)`, not null
- `definition`: `JSONB`, not null
- `provenance`: `JSONB`, nullable
- `source_agent_id`: `String(255)`, nullable
- `created_at`: `DateTime(timezone=True)`, not null, server default `now()`
- `updated_at`: `DateTime(timezone=True)`, not null, server default `now()`

Constraints:
- check: `ck_data_types_kind` enforcing `kind IN ('struct', 'enum', 'typedef')`

Relationships:
- many-to-one to `targets`
