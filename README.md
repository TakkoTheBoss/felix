# Felix

<img align="center" src="felix-mascot.png" width="50%" alt="Felix Mascot" />

Felix is an append-only temporal fact engine.

It stores immutable facts.
It derives state from time.
It guarantees deterministic reconstruction.

Felix is built around a simple rule:

> State is not stored. State is computed.

This repository contains:

* The Felix C++ reference implementation
* Native integration with Hachi
* Cat pictures

***

# What Is Felix

Felix implements a canonical temporal fact model.

Instead of updating rows, Felix records facts:

```
(record_id, field, value, timestamp)
```

Current state is derived by selecting the most recent fact per field.

Facts never mutate.
History never disappears.
State can always be rebuilt.

Also, Felix is named after a long since deceased, large gray tabby cat named "Felix", who grew to be 40 pounds. A chonk of the most legendary variety.

***

# Why Felix Exists

Most databases treat state as something you update.

You insert a row.
You update a column.
You delete a record.

Over time, the database reflects the latest version of truth.

If you want history, you bolt it on:

* Audit tables
* Change tracking
* Version columns
* Triggers
* Soft deletes

History becomes an accessory to mutation.

Felix starts from a different premise.

It never updates a field.
It never overwrites a value.
It never deletes a fact.

Instead of mutating state, Felix appends facts.

If a value changes from 6 to 7, Felix records:

```
value = 6 @ t1
value = 7 @ t2
```

Current state is simply:

> the most recent fact per field

That sounds simple.
But it changes the nature of the system.

There is no ambiguity about what happened.
There is no silent overwrite.
There is no question about reconstruction.

If something looks wrong, you replay history.
If ingestion arrives out of order, state remains correct.
If two systems ingest the same facts, they compute the same result.

---

## Not “Just” Append-Only

It is easy to look at this and say:

“Oh, it’s just an append-only table.”
“Oh, it’s just event sourcing.”
“Oh, it’s just adding timestamps.”

Felix is related to those ideas, but it goes further.

Felix enforces canonical identity.

Every value is normalized before storage.
Every canonical value has a deterministic identity hash.
Identical semantic values collapse to the same identity across the entire system.

State derivation is not convention.
It is rule-based and deterministic.

Given identical facts, conforming implementations must produce identical state.

Out-of-order ingestion cannot corrupt derived state.
Rebuilding from scratch must produce the same result as incremental updates.

This is not “data with timestamps.”

It is a deterministic temporal fact model.

The timestamp is not metadata.
It is the ordering rule that defines truth.

---

## Why This Matters

In many systems, subtle errors hide in mutation.

A value flips briefly.
A threshold oscillates.
A parameter changes and changes back.

If you only store the latest state, the pattern disappears.

Felix preserves every assertion in order.

That means you can:

* Reconstruct any point in time
* Analyze behavioral drift
* Detect instability across windows
* Prove what was known and when
* Rebuild state without trusting cached projections

You are not guessing from snapshots.
You are evaluating truth over time.

---

## When Felix Makes Sense

Felix is ideal when:

* Correctness over time matters
* Mutation must not erase history
* Determinism is required
* Reconstruction must be provable
* Auditability is a first-class concern

It favors:

Determinism over convenience
History over overwrite
Identity over representation
Explicit facts over implicit state

Felix does not try to be everything.

It does one thing carefully:

It preserves truth over time without mutation.


***

# Architecture Overview

Felix separates four logical layers:

```
Input
  ↓
Canonicalization
  ↓
Identity Hash (SHA-256)
  ↓
Immutable Facts
  ↓
Derived Current State
```

Facts are append-only.
Current state is a projection.

Rebuilding state from facts must always produce identical results.

***

# [Hachi](https://hdev.run/) Integration

<img src="felix+hachi.png" width="50%" alt="Felix Mascot" />

Felix integrates directly with [Hachi](https://hdev.run/).

The Hachi binding exposes Felix operations in a natural, type-safe way, allowing:

* Database initialization
* Ingest operations
* Snapshot queries
* Current state queries
* Rebuild operations

Felix becomes a native temporal engine inside Hachi applications.

No glue code.
No fragile bindings.
Just direct invocation.

This allows for additional features to be written in Hachi, and core Felix implementation to be updated in C++.

***

# Build

Requirements:

* C++20
* SQLite3
* OpenSSL
* ICU
* nlohmann/json
* Hachi toolchain

Compile:

```
hachi felix.hachi -cf "-std=c++20 -O2 -pipe -Wall -Wextra -pedantic -lsqlite3 -lssl -lcrypto -licui18n -licuuc" -build felix_hachi_test
```

Adjust include paths as needed.

***

# Basic Usage (CLI)

Felix operates in terms of records, timestamps, and immutable facts.

All timestamps are milliseconds since Unix epoch in UTC.

---

## Initialize a Database

Create a new Felix database:

```
./felix felix.db init
```

This creates:

* Schema tables
* Meta configuration for v0.3
* Required indexes

---

## Ingest a Record (Event Mode)

Insert state transitions:

```
./felix felix.db ingest 5001 1739539200000 event \
  "First Name=text:Felix" \
  "Last Name=text:Cat" \
  "Age=int:6" \
  "Active=bool:true"
```

Event mode:

* Inserts only if value differs from current
* Suppresses identical updates
* Still records out-of-order historical facts

---

## Ingest a Record (Observe Mode)

Record repeated measurements:

```
./felix felix.db ingest 5001 1739539300000 observe \
  "Age=int:6"
```

Observe mode:

* Always inserts a fact
* Requires unique (record_id, field_id, ts_ms)
* Does not suppress identical values

Use observe for telemetry.
Use event for state transitions.

---

## NDJSON Bulk Import

Felix supports streaming NDJSON input.

Example `input.ndjson`:

```
{"record_id":5001,"ts_ms":1739539200000,"mode":"event","fields":{"First Name":{"t":"text","v":"Felix"},"Age":{"t":"int","v":14}}}
{"record_id":5002,"ts_ms":1739539200000,"mode":"event","fields":{"First Name":{"t":"text","v":"Oscar"},"Age":{"t":"int","v":11}}}
```

Import:

```
./felix felix.db import input.ndjson
```

During import:

* Values are canonicalized
* Identity hashes are computed
* Facts are appended
* Current state is updated atomically

If any record in a transaction fails validation, the entire ingest is rejected.

---

## Snapshot Current State

Query a record at a timestamp:

```
./felix felix.db snapshot 5001 2000000000000
```

Example output:

```
{
  "record_id": 5001,
  "ts_ms": 2000000000000,
  "fields": {
    "First Name": {
      "t": "text",
      "canon": "Luke",
      "fact_ts_ms": 1739539200000
    },
    "Age": {
      "t": "int",
      "canon": "6",
      "fact_ts_ms": 1739539200000
    }
  }
}
```

If a field has never been set, it does not appear.

If a field is explicitly set to null, it appears with `"t": "null"`.

---

## Export Fact History

Retrieve immutable fact history:

```
./felix felix.db history 5001
```

Example:

```
{
  "record_id": 5001,
  "facts": [
    {
      "ts_ms": 1739539200000,
      "mode": "event",
      "field": "Age",
      "value": { "t": "int", "canon": "6" }
    },
    {
      "ts_ms": 1739540000000,
      "mode": "event",
      "field": "Age",
      "value": { "t": "int", "canon": "7" }
    }
  ]
}
```

Facts are never mutated or deleted.

---

## Rebuild Derived State

Recompute current state from immutable facts:

```
./felix felix.db rebuild_current
```

Rebuild guarantees:

* Deterministic output
* Equivalent results to incremental ingest
* Integrity validation

---

## Example Workflow

```
./felix felix.db init
./felix felix.db ingest 1 1000 event "Age=int:6"
./felix felix.db ingest 1 2000 event "Age=int:7"
./felix felix.db snapshot 1 3000
```

Result:

```
Age = 7
```

Out-of-order example:

```
./felix felix.db ingest 1 1500 event "Age=int:5"
```

State remains:

```
Age = 7
```

History now contains:

* Age=6 @ 1000
* Age=5 @ 1500
* Age=7 @ 2000

---

## Limits

Default safety limits include:

* Max 256 fields per ingest
* Max 1 MiB text value
* Max 4 MiB bytes value
* Max 2 MiB NDJSON line

Inputs exceeding limits are rejected.

***

# Event Mode vs Observe Mode

Event mode suppresses identical updates.

If Age is already 6 and you ingest Age=6 again in event mode, no new fact is recorded.

Observe mode records every measurement, even if unchanged.

Use observe for telemetry.
Use event for state transitions.

***

# Canonicalization Rules

Felix canonicalizes before identity hashing.

* Text: UTF-8, NFC normalized, trimmed outer whitespace
* Int: canonical decimal representation
* Float: IEEE 754 binary64, Dragonbox shortest round-trip
* Bool: true or false
* UUID: lowercase RFC 4122
* Bytes: raw canonical blob
* JSON: reserved in v0.3

Identity hash:

```
SHA256(type_tag || 0x00 || canonical_value)
```

Two equal values always produce the same identity.

***

# Guarantees

Felix guarantees:

* Immutable fact storage
* Deterministic state derivation
* Atomic ingest
* Out-of-order safety
* Strict uniqueness per (record_id, field_id, ts_ms)
* Snapshot reproducibility

Given identical inputs, conforming implementations must produce identical outputs.

***

# Use Cases

Felix is well suited for:

* Cellular control plane capture
* Configuration drift tracking
* Telemetry systems
* Audit logging
* Forensic reconstruction
* High-integrity temporal storage

***

# Specification

Felix follows the Felix Open Specification v0.3.

The specification defines:

* Canonicalization
* Hash derivation
* Timestamp semantics
* Ingestion rules
* Snapshot semantics
* Interoperability guarantees

Independent implementations are encouraged.

***

# Design Philosophy

Felix prioritizes:

Correctness over mutation
Identity over representation
History over overwrite
Determinism over convenience

It is not a distributed database.
It is not a query engine.
It is a temporal fact model.

***

# Project Status

Felix is actively evolving.

Version 0.3 aligns with the [current open specification](https://doi.org/10.5281/zenodo.18666474).

Breaking changes may occur before 1.0.

***

# License

[Apache 2.0

***

# Closing

Facts are immutable.
State is derived.
Identity is canonical.
Time is respected.

That is Felix.

Also, this is Felix, the original one:

<img src="felix+family.jpeg" width="60%" alt="Felix Mascot" />
