defmodule Ueberauth.Strategy.Cognito.JwtVerifierTest do
  use ExUnit.Case

  @test_private_key_1 """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAt4O2goXo+KNUQhV6l52gtVddeN/8Fts+AFn6V7e5LzEX9zlQ
  2WbvMqb2/Jk7B30I2BRGPSo2ugrRJ1VwGjCYL95OuOWAKIxTqPtMfdk6sNbSxqyb
  dHDYcWA2HWx0tgYOe7dRcNUT8EOh1oy5BMaMorsHwVGM+JDMkCGoWnS1oj0lWlR0
  qLGh1SNkx4BxwwhBug2yJrUwy3q1BP1CMR7tEswciHQp19qJiJzMRNCFhZqW9xlZ
  7IZvohKPQVQdkcbgT0QpNgL1TwGfsYyxrb/7lkT4di8WJHYYTs+VqUQCbrfTeq/0
  /vTN7jymfhWG60E/2Yk5sFweOmK7X+gVKoVXQQIDAQABAoIBAQCzfws3I4+6EtdJ
  RAUC41TbyrZMkpjaKlu8sEWjIrrpI9XTJKal3n68Rn9yltYb/vp1j28cSHv7ALWP
  CYx6sWlJ+OF7DE+MWaVCtXod5in36keDuDTdcbrjOj30Da8ik037SFVKTcAQ07Yq
  Sr51o1bPnKx7NC70uXy8xY8L2vgF1Kxx+/d9KVKVXIigU8o8eADSdRmaYaIJLYnf
  57979D+wFnhHywPkTvD3EXirgj9LjBKoS1ivIX/QwEE+rStR+g4mnNGdV0TfH5cb
  F+LK/SuUUU8q1hy8ASdH92Q/DT5yM1c0rU4qaTPEn2EasF6+VJ8SMoPpyqzOJozH
  0LalKfgBAoGBAOQcCouUU1sO6xVzGz8wzvWv5OXnIt/hYjokKPMI6DEA/P1oIRgg
  lEnV6xot6glLRyvlPLiDXCgA7bM2PUveYoM8fYDhThFaYQc25+djJ/rQdGhRxvoM
  Q2nqiN4y2PPJB34gy2FkIGmIgwxLVmNjUEiBQRts0uCHDS6oCxAU9AVhAoGBAM3z
  0l36DAZKUy/ldVyNHnZvLLgniG0ZKIe7YvLE/zuHceieveh/DoIxJ6MBbUiAysVt
  pL9mri2EoQ/F7PtZi7VWhzSssNsk4GeunvOzrrNYnf9pjCBFem8IPoVXNsZI5ssA
  6aMb9l6LG9ziOJhyJYRPFP/On8NCpwAJdpz8lL3hAoGBAKhhzqL0DYfk/kFqI43E
  wLD5czUGJmcu3yxd7uBgDc3GlfmU+QDvY6cRQqejhuPvbo0HfYgSZ1+cN9qXSi4L
  7ZpEd7xAFDmZBpClxg+20RdC8vriisefb8/qcbfbvuxN07sWCCtPFuHwBBR6ND3P
  XL74so/FB/D3oBJ1txza6rphAoGAGlgI3aqBZUCWmXbRZ1BJyD56SugLpGDmdU47
  3u/h8fxmTqoXgqjV80NUXZ5uGysWROC8hRseRoZDj9/ya0hN/Zke3FcGnFGAPuLw
  RB4Ex74bH7Ohj/MzMQat8KJySDTFCMyKFioafoduvfdV4/Id6GmxNvN4LiLVd8S+
  HmCUqiECgYBFnVjvXRyQkrxtw4BH+rmtne6ykMDbEtfdk3mHlAQ2MRi64KtFGpTl
  i++mVLwWx0U2TCGe8p5xh/u7PqIlaqClmXbK1UWAB9MZGF4wFLe4nILGFufmS+Aa
  XPa0cQFQS5K0Vjgq++qJZetMYR6VRh+qYk9ALDF/QSxhplpfde+alQ==
  -----END RSA PRIVATE KEY-----
  """

  @test_private_key_2 """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpQIBAAKCAQEAoATG/29PnyAdrXesOxDuwUcl866iNLYJUc95LXaIC/g4UMg/
  SFEMWScrxOtlUH+khLMEfIXUYz0UeR6cgB+Jy9UvnOKyA7C3VtT7F7WsX6ctDE3Y
  3mbfHq1JweczVYDRUrF9O/en2ou3T33YXtgq2gyW+QXSnEESS0AxDPTQEeptIXSO
  cIbH6DLVs+r08lRh62S06IBVb3ICbkBfMQOKaHfpaL1Vmk+SjzRaQuMbUZM/o4nv
  2ip0ucf3dJdb4Rsdem241ccPBvw0CVzvSGdK5o16i4AGVmq7p4tk0x0NDC31cmDS
  BNeviZeG+OQFUSMbPRlvhLvha0o0de6J0jftpwIDAQABAoIBAQCfxkVgNSdeLjYT
  x4Mr8utCByVo2/zP/tbtXeiTsV+D/BNW7arqLSrUNd1pINUnfFuruAeJwiLf99Pi
  X+NJtrPi13lT/7JZJvDY/Y29DcQQOh8rwusAndy4h7Q2rQA/poDbPada4hwyhgDB
  mVka0mJvF9UCzoKNTBfVFUIkuqiqyUCAJsSGWPAry7+qc9RIYzyep1YofBh2lrZu
  xt/thFx9P1yf1GUWPIpG/ySB5EySAZQAwBpyrC7PPEsmefrLnbG2rGeJVFHoaFLz
  /pIfoK3XOZu395Caaw8965OytRPZdDDLgmHXna7i3yRLRefqqBCnXjx2bb26gZgw
  t322QbKxAoGBAMs2NJrrsIbG5T0f84lKk5OmjoBvEZznMjJnJwttzUnxUzaIp0vb
  ZNPBLLg7A/Liz5GhjBsJuHQhMXoy0Y6B4E7MFsfy00F9SHQcUF6+MP8MRUSQDWgm
  TNoL4ETRIQlNa/Dhv0qEWIa57hP+irLuxEhMLcMocVEPEM41XDUl2Z+vAoGBAMmW
  L8mXggMIjhsQOfqo1rS7EfjGhkex7cFF50623jBnUrrN9gJxdio1BwtMi+jG15ez
  CTECUqj+SreRjYZWKc/HZYNP2A6SH8ZXNhh7ldZU7jE6CImYK3Uyw7zoYFX8B6xA
  x3jS0niG70vSytMWlIhmqVDePp2VFxFHZko2k1eJAoGBAKXwIYzQIVotWExNpwTZ
  TSEoxPzDtdI2SJs3+H4wr45N7fF+LX6YLQFtoSLfrh3McEsva8U4btMFt+1dShng
  nFY7+e5Ur4Wu1FdcN5TmIgRi9L1EFG6Tt/Xl9MC9NQjvm9EbxqUG5XM+qNbS6Fes
  +cM/0a6ne8EBWGvKzvznZ4opAoGBALWMCrGVP0OYGtMIxA6Yq/TMXR0dPaWn+qWL
  XQuo6WXSR9Fw19PPd0n/w75LS91x5ov6c5atrt//VC8KaNjJFJLJ0wR1jfFhbDhm
  JpPaCVGj33h5+WJhpxG/jES/SrNlbUuWc46+30ooy64PwxZkSZSmUGpCHUYyFTo8
  gUTo7b1xAoGAGW8MgHchyq8XF31EBeqSgX0nV3bucj3QqiT+hUS8TVWVw/o+AbxJ
  kGCVKx1tNHwsZbjSavLtM8Ryx5OSiMe5e8mrVz1YsTqB0aZ15bdS3HQyfebnMB8l
  5DkUK+IU/JQaxLQ6tpW8Tl+IvrDm6YKQcvItwGKMOBwhCSt5RIpNwYo=
  -----END RSA PRIVATE KEY-----
  """

  @config %Ueberauth.Strategy.Cognito.Config{
    auth_domain: "test_domain",
    client_id: "test_client_id",
    client_secret: "test_client_secret",
    user_pool_id: "user_pool_id",
    aws_region: "aws_region",
    http_client: :hackney,
    jwt_verifier: Ueberauth.Strategy.Cognito.JwtVerifier
  }

  describe "verify/3" do
    test "verifies a correctly-signed JWT" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.to_public(rsa_private_jwk)

      jws = valid_jws()
      jwt = valid_jwt()

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:ok, ^jwt} =
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end

    test "doesn't verify a JWT signed with the wrong key" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.from_pem(@test_private_key_2) |> JOSE.JWK.to_public()

      jws = valid_jws()
      jwt = valid_jwt()

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:error, :invalid_jwt} ==
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end

    test "doesn't verify a JWT when the aud doesn't match the client ID" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.to_public(rsa_private_jwk)

      jws = valid_jws()
      jwt = %{valid_jwt() | "aud" => "wrong_client_id"}

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:error, :invalid_jwt} ==
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end

    test "doesn't verify an expired JWT" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.to_public(rsa_private_jwk)

      jws = valid_jws()
      jwt = %{valid_jwt() | "exp" => System.system_time(:seconds) - 500}

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:error, :invalid_jwt} ==
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end

    test "doesn't verify when the issuer is wrong" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.to_public(rsa_private_jwk)

      jws = valid_jws()
      jwt = %{valid_jwt() | "iss" => "some_other_issuer"}

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:error, :invalid_jwt} ==
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end

    test "doesn't verify when the token_use is not 'id' or 'access'" do
      rsa_private_jwk = JOSE.JWK.from_pem(@test_private_key_1)
      rsa_public_jwk = JOSE.JWK.to_public(rsa_private_jwk)

      jws = valid_jws()
      jwt = %{valid_jwt() | "token_use" => "some_other_purpose"}

      {_algo_meta, signed_jwt} =
        JOSE.JWT.sign(rsa_private_jwk, jws, jwt)
        |> JOSE.JWS.compact()

      assert {:error, :invalid_jwt} ==
               Ueberauth.Strategy.Cognito.JwtVerifier.verify(
                 signed_jwt,
                 %{"keys" => [rsa_public_jwk]},
                 @config
               )
    end
  end

  defp valid_jws do
    %{
      "alg" => "RS256"
    }
  end

  defp valid_jwt do
    %{
      "iss" => "https://cognito-idp.#{@config.aws_region}.amazonaws.com/#{@config.user_pool_id}",
      "exp" => System.system_time(:seconds) + 500,
      "aud" => @config.client_id,
      "token_use" => "id"
    }
  end
end
