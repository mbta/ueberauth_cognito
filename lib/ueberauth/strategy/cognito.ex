defmodule Ueberauth.Strategy.Cognito do
  @moduledoc """
  Implements an `Ueberauth.Strategy` for AWS Cognito.

  Several options are available for configuring the strategy. The main keys you need to
  worry about are:

  * `auth_domain`
  * `client_id`
  * `client_secret`
  * `user_pool_id`
  * `aws_region`

  These should all be available from your AWS Cognito setup. Additionally, there are a
  couple of options specifying what modules to use for some particular functions:

  * `http_client`
  * `jwt_verifier`

  These are mainly used for dependency injection when testing and users of this library
  shouldn't have to concern themselves with them.
  """

  use Ueberauth.Strategy,
    uid_field: "cognito:username",
    name_field: "name"

  alias Ueberauth.Strategy.Cognito.Utilities
  alias Ueberauth.Strategy.Cognito.Config

  @accepted_authorize_params [:identity_provider, :idp_identifier]

  @doc """
  Handle the request step of the strategy.
  """
  def handle_request!(conn) do
    %{
      auth_domain: auth_domain,
      client_id: client_id,
      scope: scope
    } = Config.get_config(otp_app(conn))

    optional_params =
      @accepted_authorize_params
      |> Enum.flat_map(fn key ->
        case Map.fetch(conn.params, Atom.to_string(key)) do
          {:ok, value} -> [{key, value}]
          _ -> []
        end
      end)

    params =
      Keyword.merge(
        optional_params,
        response_type: "code",
        client_id: client_id,
        redirect_uri: callback_url(conn),
        scope: scope || "openid profile email"
      )
      |> with_state_param(conn)

    url = "https://#{auth_domain}/oauth2/authorize?" <> URI.encode_query(params)

    conn
    |> redirect!(url)
  end

  @doc """
  Handle the callback step of the strategy.

  Note that if the `refresh_token` param set in your `conn`, this will attempt to use the
  given refresh token rather than the normal Cognito flow.
  """
  def handle_callback!(%Plug.Conn{params: %{"refresh_token" => refresh_token}} = conn) do
    config = Config.get_config(otp_app(conn))

    with {:ok, token} <- request_token_refresh(refresh_token, config) do
      extract_and_verify_token(conn, token, config)
    else
      {:error, :cannot_refresh_access_token} ->
        set_errors!(
          conn,
          error("refresh_token_failure", "Non-200 error code from AWS when using refresh token")
        )
    end
  end

  def handle_callback!(%Plug.Conn{} = conn) do
    conn
    |> fetch_session()
    |> exchange_code_for_token()
  end

  defp exchange_code_for_token(%Plug.Conn{params: %{"code" => code}} = conn) do
    config = Config.get_config(otp_app(conn))

    with {:ok, token} <- request_token(conn, code, config) do
      extract_and_verify_token(conn, token, config)
    else
      {:error, :cannot_fetch_tokens} ->
        set_errors!(conn, error("aws_response", "Non-200 error code from AWS"))
    end
  end

  defp exchange_code_for_token(conn) do
    set_errors!(conn, error("no_code", "Missing code param"))
  end

  defp extract_and_verify_token(conn, token, config) do
    with {:ok, jwks} <- request_jwks(config),
         {:ok, id_token} <-
           config.jwt_verifier.verify(
             token["id_token"],
             jwks,
             config
           ) do
      conn
      |> put_private(:cognito_token, token)
      |> put_private(:cognito_id_token, id_token)
    else
      {:error, :cannot_fetch_jwks} ->
        set_errors!(conn, error("jwks_response", "Error fetching JWKs"))

      {:error, :invalid_jwt} ->
        set_errors!(conn, error("bad_id_token", "Could not validate JWT id_token"))
    end
  end

  defp request_jwks(config) do
    response =
      config.http_client.request(
        :get,
        Utilities.jwk_url_prefix(config) <> "/.well-known/jwks.json"
      )

    case process_json_response(response, config.http_client) do
      {:ok, decoded_json} -> {:ok, decoded_json}
      {:error, _} -> {:error, :cannot_fetch_jwks}
    end
  end

  defp request_token(conn, code, config) do
    params = %{
      grant_type: "authorization_code",
      code: code,
      client_id: config.client_id,
      redirect_uri: callback_url(conn)
    }

    response = post_to_token_endpoint(params, config)

    case process_json_response(response, config.http_client) do
      {:ok, decoded_json} -> {:ok, decoded_json}
      {:error, _} -> {:error, :cannot_fetch_tokens}
    end
  end

  defp request_token_refresh(refresh_token, config) do
    params = %{
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: config.client_id,
      client_secret: config.client_secret
    }

    response = post_to_token_endpoint(params, config)

    case process_json_response(response, config.http_client) do
      {:ok, decoded_json} -> {:ok, decoded_json}
      {:error, _} -> {:error, :cannot_refresh_access_token}
    end
  end

  defp post_to_token_endpoint(params, config) do
    auth = Base.encode64("#{config.client_id}:#{config.client_secret}")

    config.http_client.request(
      :post,
      "https://#{config.auth_domain}/oauth2/token",
      [
        {"content-type", "application/x-www-form-urlencoded"},
        {"authorization", "Basic #{auth}"}
      ],
      URI.encode_query(params)
    )
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

  @doc """
  Returns standard `Ueberauth.Auth.Credentials` struct. The `other` key will be a map
  including a `groups` key, which is a list of any groups the user is associated with in
  Cognito
  """
  def credentials(conn) do
    token = conn.private.cognito_token
    id_token = conn.private.cognito_id_token

    expires_at =
      if token["expires_in"] do
        System.system_time(:second) + token["expires_in"]
      end

    %Ueberauth.Auth.Credentials{
      token: token["access_token"],
      refresh_token: token["refresh_token"],
      expires: !!expires_at,
      expires_at: expires_at,
      other: %{groups: id_token["cognito:groups"] || []}
    }
  end

  @doc """
  Returns the username given in the Cognito response.
  """
  def uid(conn) do
    conn.private.cognito_id_token[option(conn, :uid_field)]
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    id_token = conn.private[:cognito_id_token]

    %Ueberauth.Auth.Info{
      email: id_token["email"],
      name: id_token[option(conn, :name_field)],
      first_name: id_token["given_name"],
      last_name: id_token["family_name"],
      nickname: id_token["nickname"],
      location: id_token["address"],
      description: id_token["description"],
      image: id_token["picture"],
      phone: id_token["phone_number"],
      birthday: id_token["birthdate"]
    }
  end

  @doc """
  The `raw_info` key of the returned struct includes everything from the raw Cognito
  response in `cognito_id_token`.
  """
  def extra(conn) do
    %Ueberauth.Auth.Extra{
      raw_info: conn.private.cognito_id_token
    }
  end

  @doc """
  Handles the cleanup step of the strategy.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:cognito_token, nil)
    |> put_private(:cognito_id_token, nil)
  end

  defp otp_app(conn) do
    default_app = :ueberauth

    if opts = options(conn) do
      Keyword.get(opts, :otp_app, default_app)
    else
      default_app
    end
  end

  defp option(conn, key) do
    Map.get(Config.get_config(otp_app(conn)), key) || Keyword.get(default_options(), key)
  end
end
