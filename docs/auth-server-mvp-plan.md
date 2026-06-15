# Auth Server MVP Plan (OIDC)

GeeKEN Gate is now modeled as an internal OpenID Connect Provider. Historical
custom login/code-exchange examples have been removed from this document; use the
README for the current client integration flow.

Current application-facing endpoints:

- `GET /.well-known/openid-configuration`
- `GET /authorize`
- `POST /token`
- `GET /jwks.json`
- `GET /userinfo`

Applications must identify users by GeeKEN Gate `(iss, sub)`. GitHub user IDs,
Google `sub` values, and email addresses are upstream/member attributes and must
not be application primary identifiers.
