# HyperShift job registry

This command discovers HyperShift CI jobs from an `openshift/release` checkout
and writes a declarative registry to standard output.

## Build and run

```console
make build
./bin/job-registry > job-registry.yaml
./bin/job-registry -format json > job-registry.json
```

Output defaults to YAML. The `-format` flag accepts `yaml` or `json`.

The release checkout defaults to `~/Projects/openshift-release`; use
`-release-dir` to select another checkout.

## Discovery scope

Discovery includes:

- all periodics and presubmits under
  `ci-operator/jobs/openshift/hypershift`;
- jobs elsewhere in `ci-operator/jobs` whose Prow context or CI target matches
  `hypershift-*-conformance`.

## Design principles and invariants

- A job is the unit of record. The registry does not encode report categories;
  consumers compose reports by filtering job properties.
- Each Prow job appears at most once and has a globally unique stable ID. Jobs
  are emitted in ID order so unchanged inputs produce stable output.
- Every job remains traceable to its generated definition in
  `openshift/release`.
- Multi-valued facts such as versions and platforms remain arrays. Unknown or
  inapplicable values are empty, null, or omitted rather than represented by
  sentinel values such as `main`.
- Type-specific properties are nested. Presubmit behavior does not appear on
  periodic jobs.
- Job discovery depends only on the selected `openshift/release` checkout. The
  command does not clone repositories or query live services.
- Sippy URLs are deterministic navigation hints and never assertions about
  current Sippy data availability.
- YAML and JSON are equivalent serializations of the versioned registry API.

## Registry API

The versioned registry schema and field semantics are defined by the documented
Go types in [main.go](main.go).

## Sippy links

Sippy URLs are generated deterministically without querying Sippy. Presubmits
link to the `Presubmits` analysis view, and release periodics link to their
release view. Periodics without a concrete release have `sippy_url: null`.

A Sippy URL is a navigation hint, not evidence that Sippy has data for the job.
Sippy's public jobs API is time-windowed and cannot reliably distinguish an
unsupported job from one that has not run recently. Use `-sippy-base-url` to
generate links for another Sippy deployment.
