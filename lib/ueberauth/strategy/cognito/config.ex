defmodule Ueberauth.Strategy.Cognito.Config do
  @enforce_keys [:auth_domain, :client_id, :client_secret, :user_pool_id, :aws_region]
  defstruct @enforce_keys

  def get_config do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Cognito) || %{}

    struct(
      __MODULE__,
      Map.new(@enforce_keys, fn c ->
        {c, config_value(config[c])}
      end)
    )
  end

  defp config_value(value) when is_binary(value), do: value
  defp config_value({m, f, a}), do: apply(m, f, a)
end
