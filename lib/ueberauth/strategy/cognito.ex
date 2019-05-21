defmodule Ueberauth.Strategy.Cognito do
  use Ueberauth.Strategy
  alias Ueberauth.Strategy.Cognito.Utilities
  alias Ueberauth.Strategy.Cognito.Config

  def handle_request!(conn) do
    state = :crypto.strong_rand_bytes(32) |> Base.encode16()

    %{
      auth_domain: auth_domain,
      client_id: client_id
    } = Config.get_config()

    params = %{
      response_type: "code",
      client_id: client_id,
      redirect_uri: callback_url(conn),
      state: state,
      # TODO - make dynamic (accepting PRs!):
      scope: "openid profile email"
    }

    url = "https://#{auth_domain}/oauth2/authorize?" <> URI.encode_query(params)

    conn
    |> fetch_session()
    |> put_session("cognito_state", state)
    |> redirect!(url)
    |> halt()
  end

  def handle_callback!(%Plug.Conn{params: %{"state" => state}} = conn) do
    expected_state =
      conn
      |> fetch_session()
      |> get_session("cognito_state")

    conn =
      if state == expected_state do
        exchange_code_for_token(conn)
      else
        set_errors!(conn, error("bad_state", "State parameter doesn't match"))
      end

    conn
    |> fetch_session()
    |> delete_session("cognito_state")
  end

  def handle_callback!(conn) do
    set_errors!(conn, error("no_state", "Missing state param"))
  end

  defp exchange_code_for_token(%Plug.Conn{params: %{"code" => code}} = conn) do
    http_client = Application.get_env(:ueberauth_cognito, :__http_client, :hackney)

    jwt_verifier =
      Application.get_env(
        :ueberauth_cognito,
        :__jwt_verifier,
        Ueberauth.Strategy.Cognito.JwtVerifier
      )

    config = Config.get_config()

    with {:ok, token} <- request_token(conn, code, http_client, config),
         {:ok, jwks} <- request_jwks(http_client, config),
         {:ok, id_token} <-
           jwt_verifier.verify(
             token["id_token"],
             jwks,
             config
           ) do
      conn
      |> put_private(:cognito_token, token)
      |> put_private(:cognito_id_token, id_token)
    else
      {:error, :cannot_fetch_tokens} ->
        set_errors!(conn, error("aws_response", "Non-200 error code from AWS"))

      {:error, :cannot_fetch_jwks} ->
        set_errors!(conn, error("jwks_response", "Error fetching JWKs"))

      {:error, :invalid_jwt} ->
        set_errors!(conn, error("bad_id_token", "Could not validate JWT id_token"))
    end
  end

  defp exchange_code_for_token(conn) do
    set_errors!(conn, error("no_code", "Missing code param"))
  end

  defp request_jwks(http_client, config) do
    response =
      http_client.request(
        :get,
        Utilities.jwk_url_prefix(config) <> "/.well-known/jwks.json"
      )

    case process_json_response(response, http_client) do
      {:ok, decoded_json} -> {:ok, decoded_json}
      {:error, _} -> {:error, :cannot_fetch_jwks}
    end
  end

  defp request_token(conn, code, http_client, config) do
    auth = Base.encode64("#{config.client_id}:#{config.client_secret}")

    params = %{
      grant_type: "authorization_code",
      code: code,
      client_id: config.client_id,
      redirect_uri: callback_url(conn)
    }

    response =
      http_client.request(
        :post,
        "https://#{config.auth_domain}/oauth2/token",
        [
          {"content-type", "application/x-www-form-urlencoded"},
          {"authorization", "Basic #{auth}"}
        ],
        URI.encode_query(params)
      )

    case process_json_response(response, http_client) do
      {:ok, decoded_json} -> {:ok, decoded_json}
      {:error, _} -> {:error, :cannot_fetch_tokens}
    end
  end

  defp process_json_response(response, http_client) do
    with {:ok, 200, _headers, client_ref} <- response,
         {:ok, body} <- http_client.body(client_ref),
         decoded_json <- Jason.decode!(body) do
      {:ok, decoded_json}
    else
      _ ->
        {:error, :invalid_response}
    end
  end

  def credentials(conn) do
    token = conn.private.cognito_token

    expires_at =
      if token["expires_in"] do
        System.system_time(:seconds) + token["expires_in"]
      end

    %Ueberauth.Auth.Credentials{
      token: token["access_token"],
      refresh_token: token["refresh_token"],
      expires: !!expires_at,
      expires_at: expires_at
    }
  end

  def uid(conn) do
    conn.private.cognito_id_token["cognito:username"]
  end

  def info(_conn) do
    %Ueberauth.Auth.Info{}
  end

  def extra(conn) do
    %Ueberauth.Auth.Extra{
      raw_info: conn.private.cognito_id_token
    }
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:cognito_token, nil)
    |> put_private(:cognito_id_token, nil)
  end
end
