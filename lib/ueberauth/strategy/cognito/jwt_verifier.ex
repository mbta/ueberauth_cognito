defmodule Ueberauth.Strategy.Cognito.JwtVerifier do
  @moduledoc """
  Utilities for working with JSON Web Tokens
  """

  alias Ueberauth.Strategy.Cognito.Utilities

  @doc "Verifies that a JWT is valid: the signature is correct,
  and the audience is the AWS client_id"
  def verify(jwt, jwks, client_id, aws_region, user_pool_id) do
    individual_jwks = Enum.map(jwks["keys"], &JOSE.JWK.from(&1))

    with {:ok, claims_json} <- verified_claims(individual_jwks, jwt),
         {:ok, claims} <- Jason.decode(claims_json),
         true <- claims["aud"] == client_id,
         true <- claims["exp"] > System.system_time(:seconds),
         true <- claims["iss"] == Utilities.jwk_url_prefix(aws_region, user_pool_id),
         true <- claims["token_use"] in ["id", "access"] do
      {:ok, claims}
    else
      _ ->
        {:error, :invalid_jwt}
    end
  end

  defp verified_claims(jwks, jwt) do
    Enum.find_value(jwks, fn jwk ->
      case JOSE.JWS.verify_strict(jwk, ["RS256"], jwt) do
        {true, claims_json, _} -> {:ok, claims_json}
        _ -> nil
      end
    end)
  end
end
