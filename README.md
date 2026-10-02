# crowsi-credential-agent

Provide a dedicated local enrollment endpoint for adding credentials to an authorized custody service.

## What you can do

- Validate a bounded enrollment request.
- Connect enrollment to the configured local-control and broker interfaces.

## Current scope

This endpoint is enrollment-only. Its Unix socket and owner authorization must be provisioned explicitly.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
