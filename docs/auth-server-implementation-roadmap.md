# Auth Server Implementation Roadmap (OIDC)

GeeKEN Gate's application integration path is standard OIDC Authorization Code
Flow with PKCE. See `README.md` and `plan.md` Issue 4 for the current smoke
client, endpoint, and operational guidance.

Current implementation priorities:

1. OIDC discovery and JWKS publication.
2. `/authorize` with `provider=github` or `provider=google` and PKCE `S256`.
3. Upstream authentication/admission for GitHub Organization membership or
   Google ID Token + hosted-domain + member DB admission.
4. `/token` with Basic client auth, one-time authorization codes, and signed ID
   Tokens whose `sub` is GeeKEN Gate `users.user_id`.
5. Optional `/userinfo` returning the same GeeKEN Gate `sub`.

Applications are responsible for their own authorization decisions after
authentication.
