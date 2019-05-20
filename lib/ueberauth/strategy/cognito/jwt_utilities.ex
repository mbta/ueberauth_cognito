defmodule Ueberauth.Strategy.Cognito.JwtUtilities do
  @moduledoc """
  Utilities for working with JSON Web Tokens
  """

  @doc "Verifies that a JWT is valid: the signature is correct,
  and the audience is the AWS client_id"
  def verify(jwt, jwks, client_id, aws_region, user_pool_id) do
    with {:ok, claims_json} <- verified_claims(jwks["keys"], jwt),
         {:ok, claims} <- Jason.decode(claims_json),
         true <- claims["aud"] == client_id,
         true <- claims["exp"] > System.system_time(:seconds),
         true <-
           claims["iss"] == "https://cognito-idp.#{aws_region}.amazonaws.com/#{user_pool_id}",
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
