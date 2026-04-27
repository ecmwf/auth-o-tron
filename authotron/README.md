# authotron

Auth-O-Tron is an authentication and authorization gateway for web APIs.

It validates credentials from multiple providers, enriches authenticated users with roles and attributes, and issues signed JWTs that downstream services can trust.

## Workspace role

This crate is the server/application crate in the Auth-O-Tron workspace.

- `authotron`: server and HTTP application
- `authotron-types`: shared DTOs and error types
- `authotron-client`: optional Rust client for consuming Auth-O-Tron

## Documentation

- Project docs: <https://sites.ecmwf.int/docs/authotron/main/>
- Source repository: <https://github.com/ecmwf/auth-o-tron>
