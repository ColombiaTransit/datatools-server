# Transit Data Manager

[![Join the chat at https://matrix.to/#/#transit-data-tools:gitter.im](https://badges.gitter.im/repo.png)](https://matrix.to/#/#transit-data-tools:gitter.im)

The core application for IBI Group's TRANSIT-Data-Tools suite.

## Documentation

View the [latest documentation](http://conveyal-data-tools.readthedocs.org/en/latest/) at ReadTheDocs.

Note: `dev` branch docs can be found [here](http://conveyal-data-tools.readthedocs.org/en/dev/).

## Docker Image
The easiest way to get `datatools-server` running is to use the provided `Dockerfile` and `docker-compose.yml`. The `docker-compose.yml` includes both database servers that are needed. Edit the supplied configurations in the `configurations` directory to ensure the server starts correctly. Once this is done running `docker-compose up` will start Datatools and all required database servers.

## OIDC login preview

The server has opt-in OpenID Connect endpoints. They establish a Datatools
session and record the provider identity in MongoDB. Datatools API permissions
and the UI still use their existing authentication configuration during this
preview.

1. Create a confidential OIDC client with Authorization Code flow, S256 PKCE
   and RS256 ID tokens. Register the exact redirect URI
   `<application.public_url>/api/auth/oidc/callback`.
2. Set `OIDC_ENABLED=true`, `OIDC_ISSUER` (the issuer URL, such as a Keycloak realm)
   and `OIDC_CLIENT_ID` in the server environment or its `env.yml`. Provide
   `OIDC_CLIENT_SECRET` through the server process environment.
3. Set `application.public_url` to the UI and API's shared origin. Serve that
   origin and the issuer over HTTPS. HTTP loopback URLs are supported for local
   development.

Open `/api/auth/oidc/login` at that origin to start login. The callback redirects
back to the origin. `GET /api/auth/oidc/session` returns the current identity
and its session expiry. `POST /api/auth/oidc/logout` requires the matching
browser Origin header and removes the local session. It does not end the
provider's SSO session. OIDC access, refresh and ID tokens are kept out of
the browser and MongoDB.

## Getting in touch

We have a Gitter [space](https://matrix.to/#/#transit-data-tools:gitter.im) for the full TRANSIT-Data-Tools project where you can post questions and comments.
