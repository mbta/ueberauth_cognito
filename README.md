# Ueberauth Cognito

[![Build Status](https://github.com/mbta/ueberauth_cognito/actions/workflows/elixir.yml/badge.svg?branch=master)](https://github.com/mbta/ueberauth_cognito/actions/workflows/elixir.yml)

> An Ueberauth Strategy for AWS Cognito.

## Installation

Add `:ueberauth` and `:ueberauth_cognito` to your `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:ueberauth, "~> 0.7"},
    {:ueberauth_cognito, "~> 0.3"}
  ]
end
```

Configure Ueberauth to use this strategy:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    cognito: {Ueberauth.Strategy.Cognito, []}
  ]
```

and configure the required values:

```elixir
config :ueberauth, Ueberauth.Strategy.Cognito,
  auth_domain: {System, :get_env, ["COGNITO_DOMAIN"]},
  client_id: {System, :get_env, ["COGNITO_CLIENT_ID"]},
  client_secret: {System, :get_env, ["COGNITO_CLIENT_SECRET"]},
  user_pool_id: {System, :get_env, ["COGNITO_USER_POOL_ID"]},
  aws_region: {System, :get_env, ["COGNITO_AWS_REGION"]} # e.g. "us-east-1"
```

The values can be configured with an MFA, or simply a string.

Add the routes to the router:

```elixir
scope "/auth", SignsUiWeb do
  pipe_through([:redirect_prod_http, :browser])
  get("/:provider", AuthController, :request)
  get("/:provider/callback", AuthController, :callback)
end
```

and create the corresponding controller:

```elixir
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

## Configuration of settings per OTP app

If you wish to use Ueberauth in multiple OTP apps, and configure each instance of Ueberauth with a different list of Providers and settings, you will need to do some things differently. When providing configuration for Ueberauth, you should set anything that differs by OTP app under the name of your OTP app, for example:

```ex
config :my_app, Ueberauth,
  providers: [
    cognito: {Ueberauth.Strategy.Cognito, []}
  ]
```

and configure the required values for the provider (make sure to use the same otp_app name)

```elixir
config :my_app, Ueberauth.Strategy.Cognito,
  auth_domain: {System, :get_env, ["COGNITO_DOMAIN"]},
  client_id: {System, :get_env, ["COGNITO_CLIENT_ID"]},
  client_secret: {System, :get_env, ["COGNITO_CLIENT_SECRET"]},
  user_pool_id: {System, :get_env, ["COGNITO_USER_POOL_ID"]},
  aws_region: {System, :get_env, ["COGNITO_AWS_REGION"]} # e.g. "us-east-1"
```

In your controller, when using the Ueberauth plug, you should pass the `:otp_app` option, for example:

```elixir
defmodule SignsUiWeb.AuthController do
  use SignsUiWeb, :controller
  plug(Ueberauth, otp_app: :my_app)

  ...
```

## Copyright and License

Copyright (c) 2019 Massachusetts Bay Transportation Authority

Source code licensed under [MIT License](./LICENSE.md).
