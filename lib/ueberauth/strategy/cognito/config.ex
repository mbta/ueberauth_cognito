defmodule Ueberauth.Strategy.Cognito.Config do
  @moduledoc false

  @strategy_keys [
    :auth_domain,
    :client_id,
    :client_secret,
    :user_pool_id,
    :aws_region
  ]

  @dependency_keys [
    :http_client,
    :jwt_verifier
  ]

  @optional_keys [
    :uid_field,
    :name_field,
    :scope
  ]

  @enforce_keys @strategy_keys ++ @dependency_keys

  defstruct @enforce_keys ++ @optional_keys

  @doc false
  def get_config(conn) do
    options = Ueberauth.Strategy.Helpers.options(conn) || []
    otp_app = Keyword.get(options, :otp_app, :ueberauth)

    config =
      Application.get_env(otp_app, Ueberauth.Strategy.Cognito) || %{}

    strategy_config =
      Map.new(@strategy_keys, fn c ->
        {c, config_value(Keyword.get(options, c)) || config_value(config[c])}
      end)

    dependency_config = %{
      http_client: Application.get_env(:ueberauth_cognito, :__http_client, :hackney),
      jwt_verifier:
        Application.get_env(
          :ueberauth_cognito,
          :__jwt_verifier,
          Ueberauth.Strategy.Cognito.JwtVerifier
        )
    }

    optional_config =
      Map.new(@optional_keys, fn c ->
        {c, config_value(Keyword.get(options, c)) || config_value(config[c])}
      end)

    overall_config =
      optional_config
      |> Map.merge(strategy_config)
      |> Map.merge(dependency_config)

    struct(
      __MODULE__,
      overall_config
    )
  end

  defp config_value(value) when is_binary(value) or is_nil(value), do: value
  defp config_value({m, f, a}), do: apply(m, f, a)
end
