defmodule Ueberauth.Strategy.Cognito do
  use Ueberauth.Strategy
  require Logger

  def handle_request!(conn) do
    state = "#{:rand.uniform(10_000_000)}"

    %{
      auth_domain: auth_domain,
      client_id: client_id
    } = get_config()

    params = %{
      response_type: "code",
      client_id: client_id,
      redirect_uri: callback_url(conn),
      state: state,
      # TODO - make dynamic:
      scope: "openid profile email"
      # TODO: code challenge
      # code_challenge: "",
      # code_challenge_method: "S256"
    }

    url = "https://#{auth_domain}/oauth2/authorize?" <> URI.encode_query(params)

    conn
    |> fetch_session()
    |> put_session("cognito_state", state)
    |> redirect!(url)
    |> halt()
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => state}} = conn) do
    expected_state =
      conn
      |> fetch_session()
      |> get_session("cognito_state")

    conn =
      if state == expected_state do
        %{
          auth_domain: auth_domain,
          client_id: client_id,
          client_secret: client_secret
        } = get_config()

        auth = Base.encode64("#{client_id}:#{client_secret}")

        params = %{
          grant_type: "authorization_code",
          code: code,
          client_id: client_id,
          redirect_uri: callback_url(conn)
        }

        response =
          :hackney.request(
            :post,
            "https://#{auth_domain}/oauth2/token",
            [
              {"content-type", "application/x-www-form-urlencoded"},
              {"authorization", "Basic #{auth}"}
            ],
            URI.encode_query(params)
          )

        case response do
          {:ok, 200, _headers, client_ref} ->
            {:ok, body} = :hackney.body(client_ref)
            token = Jason.decode!(body)

            # TODO: verify signature
            [_header, payload, _sig] = String.split(token["id_token"], ".")
            id_token = payload |> Base.url_decode64!(padding: false) |> Jason.decode!()

            conn
            |> put_private(:cognito_token, token)
            |> put_private(:cognito_id_token, id_token)
        end
      else
        set_errors!(conn, error("bad_state", "State parameter doesn't match"))
      end

    conn
    |> fetch_session()
    |> delete_session("cognito_state")
  end

  def credentials(conn) do
    token = conn.private.cognito_token

    expires_at =
      if token["expires_in"] do
        DateTime.to_unix(DateTime.utc_now()) + token["expires_in"]
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

  defp get_config do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Cognito) || %{}

    [:auth_domain, :client_id, :client_secret]
    |> Enum.map(fn c -> {c, config_value(config[c])} end)
    |> Enum.into(%{})
  end

  defp config_value(value) when is_binary(value), do: value
  defp config_value({m, f, a}), do: apply(m, f, a)
end
