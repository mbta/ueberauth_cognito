defmodule Ueberauth.Strategy.Cognito.JwtUtilities do
  @moduledoc """
  Utilities for working with JSON Web Tokens
  """

  @doc "Verifies that a JWT is valid: the signature is correct,
  and the audience is the AWS client_id"
  def verify(jwt, jwks, client_id) do
    [header, _payload, _sig] = String.split(jwt, ".")

    key_id =
      header
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> Map.get("kid")

    jwk =
      jwks["keys"]
      |> Enum.find(&(&1["kid"] == key_id))
      |> JOSE.JWK.from()

    with {true, claims_json, _} <- JOSE.JWS.verify_strict(jwk, ["RS256"], jwt),
         {:ok, claims} <- Jason.decode(claims_json),
         true <- claims["aud"] == client_id do
      {:ok, claims}
    else
      _ ->
        {:error, :invalid_jwt}
    end
  end
end
