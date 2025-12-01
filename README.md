[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# ingress-force-ssl-require-tls

Kubewarden policy that validates Kubernetes Ingress resources using the
`force-ssl-redirect` annotation.

When enabled via settings, this policy enforces that:

- If `force-ssl-redirect` is **true**, the Ingress **must** have TLS configured.
- When TLS is configured and `force-ssl-redirect` is **true**:
  - `spec.tls[*].hosts` must match `spec.rules[*].host` one-to-one (as sets).
  - There must be at least one TLS entry.

The policy is written in Go using the Kubewarden SDK and compiled to WebAssembly
via TinyGo.

## Introduction

This repository contains a Kubewarden policy that validates `networking.k8s.io/v1`
Ingress resources.

The policy focuses on the `force-ssl-redirect` behavior commonly used by
Ingress controllers (for example, the NGINX Ingress controller).

Depending on the runtime settings, the policy enforces that Ingress objects
using `force-ssl-redirect` also have a valid TLS configuration.

## Behavior

### Settings

The policy has a single setting:

```json
{
  "validate_force_ssl_redirect": true
}
```

- `validate_force_ssl_redirect` (boolean, default: `false`)
  - When `false`: the policy does **not** enforce any TLS/host constraints and
    always accepts requests.
  - When `true`: the policy enforces the rules described below.

### Validation Rules

When `validate_force_ssl_redirect` is `true`, the policy evaluates the
annotations of the Ingress:

- It considers the following annotation keys (case-insensitive, value trimmed):
  - `nginx.ingress.kubernetes.io/force-ssl-redirect`
  - `force-ssl-redirect`
- If none of these annotations are set to `"true"`, the policy **accepts** the
  request without further checks.

If the annotation is effectively `true`, the policy enforces **all** of these
rules:

1. **TLS must be configured**
   - `spec` must be present.
   - `spec.tls` must contain at least one item.

2. **TLS hosts must match rule hosts one-to-one**
   - `spec.rules[*].host` entries are collected as a set.
     - Empty `host` values are not allowed and cause the request to be rejected.
   - `spec.tls[*].hosts` entries are collected as a set (ignoring empty
     strings).
   - The two sets must be identical:
     - Any host present in rules but missing from TLS → **rejection**.
     - Any host present in TLS but not in rules → **rejection**.

If all checks pass, the request is accepted.

## Code organization

- `settings.go`: parsing and validation of the policy settings.
- `validate.go`: core validation logic for Ingress resources, including the
  `force-ssl-redirect` and TLS/host checks.
- `main.go`: registers the `validate` and `validate_settings` entry points
  expected by Kubewarden.

## Implementation details

> **DISCLAIMER:** WebAssembly is a constantly evolving area.
> This document describes the status of the Go ecosystem as of July 2023.

Currently, the official Go compiler can't produce WebAssembly binaries that can
run **outside** the browser. Because of that, you can only build Kubewarden Go
policies with the [TinyGo](https://tinygo.org/) compiler.

Kubewarden policies need to process JSON data, for example, the policy settings
and the actual request received by Kubernetes.

TinyGo doesn't yet support the full Go Standard Library; it has limited support
of Go reflection. Because of that, it's impossible to import the official
Kubernetes Go library from upstream (for example, `k8s.io/api/core/v1`).
Importing these official Kubernetes types results in a compilation failure.

However, it's still possible to write a Kubewarden policy by using certain
third-party libraries.

This list of libraries can be useful when writing a Kubewarden policy:

- [Kubernetes Go types](https://github.com/kubewarden/k8s-objects) for TinyGo:
  the official Kubernetes Go Types can't be used with TinyGo. This module
  provides all the Kubernetes Types in a TinyGo-friendly way.
- Parsing JSON: queries against JSON documents can be written using the
  [gjson](https://github.com/tidwall/gjson) library. The library features a
  powerful query language that allows quick navigation of JSON documents and
  data retrieval.
- Generic `set` implementation: using
  [Set](https://en.wikipedia.org/wiki/Set_(abstract_data_type)) data types can
  reduce the amount of code in a policy, see the `union`, `intersection`,
  `difference`, and other operations provided by a Set implementation. The
  [mapset](https://github.com/deckarep/golang-set) library can be used when
  writing policies.

This policy also takes advantage of helper functions provided by the
[Kubewarden Go SDK](https://github.com/kubewarden/policy-sdk-go).

## Settings examples

- Disable validation (default behavior):

```json
{}
```

- Enable validation and enforce TLS and host matching when
  `force-ssl-redirect` is `true`:

```json
{
  "validate_force_ssl_redirect": true
}
```

## Testing

This policy comes with unit tests implemented using the Go testing framework.

As usual, the tests are defined in `_test.go` files. As these tests aren't part
of the final WebAssembly binary, the official Go compiler can be used to run
them.

Run unit tests:

```console
make test
```

There are also end-to-end tests that exercise the compiled WebAssembly module
using the `kwctl` CLI.

Run end-to-end tests:

```console
make e2e-tests
```

## Automation

This project has the following
[GitHub Actions](https://docs.github.com/en/actions):

- `e2e-tests`: builds the WebAssembly policy, installs the `bats` utility and
  then runs the end-to-end tests.
- `unit-tests`: runs the Go unit tests.
- `release`: builds the WebAssembly policy and pushes it to a user-defined OCI
  registry (for example, [ghcr](https://ghcr.io)).
