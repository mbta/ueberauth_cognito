defmodule Ueberauth.Strategy.Cognito.JwtUtilities do
  @moduledoc """
  Utilities for working with JSON Web Tokens
  """

  @doc "Verifies that a JWT is valid: the signature is correct,
  and the audience is the AWS client_id"
  def verify(jwt, jwks, client_id) do
    individual_jwks = Enum.map(jwks["keys"], &JOSE.JWK.from(&1))

    Enum.find_value(individual_jwks, {:error, :invalid_jwt}, fn jwk ->
      with {true, claims_json, _} <- JOSE.JWS.verify_strict(jwk, ["RS256"], jwt),
           {:ok, claims} <- Jason.decode(claims_json),
           true <- claims["aud"] == client_id do
        {:ok, claims}
      else
        _ ->
          nil
      end
    end)
  end
end
