# UeberauthCognito

[![Build Status](https://semaphoreci.com/api/v1/mbta/ueberauth_cognito/branches/master/shields_badge.svg)](https://semaphoreci.com/mbta/ueberauth_cognito)
[![Codecov](https://codecov.io/gh/mbta/ueberauth_cognito/branch/master/graph/badge.svg)](https://codecov.io/gh/mbta/ueberauth_cognito)

An Ueberauth Strategy for AWS Cognito.

## Installation

Add `:ueberauth` and `:ueberauth_cognito` to your `mix.exs`:

```ex
defp deps do
  [
    # ...
    {:ueberauth, "~> 0.1"},
    {:ueberauth_cognito, git: "https://github.com/mbta/ueberauth_cognito.git"}
  ]
end
```

Configure Ueberauth to use this strategy:

```ex
config :ueberauth, Ueberauth,
  providers: [
    cognito: {Ueberauth.Strategy.Cognito, []}
  ]
```

and configure the required values:

```ex
config :ueberauth, Ueberauth.Strategy.Cognito,
  auth_domain: {System, :get_env, ["COGNITO_DOMAIN"]},
  client_id: {System, :get_env, ["COGNITO_CLIENT_ID"]},
  client_secret: {System, :get_env, ["COGNITO_CLIENT_SECRET"]},
  user_pool_id: {System, :get_env, ["COGNITO_USER_POOL_ID"]},
  aws_region: {System, :get_env, ["COGNITO_AWS_REGION"]} # e.g. "us-east-1"
```

The values can be configured with an MFA, or simply a string.

Add the routes to the router:

```ex
scope "/auth", SignsUiWeb do
  pipe_through([:redirect_prod_http, :browser])
  get("/:provider", AuthController, :request)
  get("/:provider/callback", AuthController, :callback)
end
```

and create the corresponding controller:

```ex
defmodule SignsUiWeb.AuthController do
  use SignsUiWeb, :controller
  plug(Ueberauth)

  def callback(%{assigns: %{ueberauth_failure: _fails}} = conn, _params) do
    # what to do if sign in fails
  end

  def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
    # sign the user in or something.
    # auth is a `%Ueberauth.Auth{}` struct, with Cognito token info
    send_resp(conn, 200, "Welcome, #{auth.uid}")
  end
end
```

Note that the entry in the `router` defines the authentication callback URL, and will need to be whitelisted in the AWS Cognito User Pools settings.

## Refreshing access tokens

Cognito supports [using refresh tokens](https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/) to automatically obtain new access tokens for users whose access tokens expire. If the callback URL is called with the `refresh_token` param set, Ueberauth will attempt to use the given refresh token value to obtain a new, fresh access token.

The refresh token for an access token is issued at the same time as the access token, and is available in the `Ueberauth.Auth.Credentials` struct. Whether to use refresh tokens, and where to store them if used, is an implementation detail. Your first instinct might be to store them in a cookie, but they can sometimes exceed the maximum possible cookie size. An alternative is to store an identifier (which could be a username, or simply a random nonce) in a cookie, and create a GenServer that maps these identifiers to refresh tokens. This has the advantage of not revealing the refresh tokens to the end user, if this is a consideration.
