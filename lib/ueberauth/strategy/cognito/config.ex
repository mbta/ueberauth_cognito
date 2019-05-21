defmodule Ueberauth.Strategy.Cognito.Config do
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

  @enforce_keys @strategy_keys ++ @dependency_keys

  defstruct @enforce_keys

  def get_config do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Cognito) || %{}

    strategy_config =
      Map.new(@strategy_keys, fn c ->
        {c, config_value(config[c])}
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

    overall_config = Map.merge(strategy_config, dependency_config)

    struct(
      __MODULE__,
      overall_config
    )
  end

  defp config_value(value) when is_binary(value), do: value
  defp config_value({m, f, a}), do: apply(m, f, a)
end
