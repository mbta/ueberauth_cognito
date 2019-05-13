# UeberauthCognito

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
config :ueberauth, Ueberauth.Strategy.Cognito.OAuth,
  auth_domain: {System, :get_env, ["COGNITO_DOMAIN"]},
  redirect_uri: {System, :get_env, ["COGNITO_REDIRECT_URI"]},
  client_id: {System, :get_env, ["COGNITO_CLIENT_ID"]},
  client_secret: {System, :get_env, ["COGNITO_CLIENT_SECRET"]}
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
