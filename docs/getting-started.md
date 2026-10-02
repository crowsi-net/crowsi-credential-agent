# Using crowsi-credential-agent

Provide a dedicated local enrollment endpoint for adding credentials to an authorized custody service.

## Before you start

This endpoint is enrollment-only. Its Unix socket and owner authorization must be provisioned explicitly.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate a bounded enrollment request.
- Connect enrollment to the configured local-control and broker interfaces.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
