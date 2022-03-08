defmodule Ueberauth.Strategy.CognitoTest do
  use ExUnit.Case
  use Plug.Test
  alias Ueberauth.Strategy.Cognito

  defmodule FakeHackneySuccess do
    def request(:post, _url, _headers, _body) do
      {:ok, 200, [], :successful_post_ref}
    end

    def request(:get, "https://cognito-idp" <> _) do
      {:ok, 200, [], :success_jwks}
    end

    def body(:successful_post_ref) do
      id_token_payload =
        %{
          "email" => "foo",
          "email_verified" => false,
          "at_hash" => "hash",
          "aud" => "3rgcfma9qb6ol300sbo3e37a29",
          "auth_time" => 1_589_385_933,
          "cognito:groups" => ["ap-northeast-1_xxxx"],
          "cognito:username" => "UserName",
          "exp" => 1_589_389_533,
          "iat" => 1_589_385_933,
          "identities" => [
            %{
              "dateCreated" => "1589384379675",
              "issuer" => "urn:xxxx.com",
              "primary" => "true",
              "providerName" => "idp-name",
              "providerType" => "SAML",
              "userId" => "user-id"
            }
          ],
          "iss" => "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_xxxx",
          "name" => "UserName",
          "sub" => "xxxx",
          "token_use" => "id",
          "nickname" => "Nickname",
          "given_name" => "Given",
          "family_name" => "Family",
          "address" => "Japan",
          "picture" => "https://example.com/img",
          "phone_number" => "1234567890",
          "birthdate" => "2020-05-15"
        }
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      id_token = "header.#{id_token_payload}.signature"

      token = %{
        "access_token" => "the_access_token",
        "id_token" => id_token,
        "refresh_token" => "a_refresh_token"
      }

      {:ok, Jason.encode!(token)}
    end

    def body(:success_jwks) do
      {:ok, Jason.encode!(%{})}
    end
  end

  defmodule FakeHackneyError do
    def request(_method, _url, _headers, _body) do
      {:ok, 403, [], :error_ref}
    end

    def body(:error_ref) do
      {:ok, ""}
    end
  end

  defmodule FakeHackneyJwkError do
    def request(:post, _url, _headers, _body) do
      {:ok, 200, [], :successful_post_ref}
    end

    def request(:get, "https://cognito-idp" <> _) do
      {:ok, 404, [], :failure_jwks}
    end

    def body(:successful_post_ref) do
      id_token_payload =
        %{"email" => "foo"}
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      id_token = "header.#{id_token_payload}.signature"

      token = %{
        "access_token" => "the_access_token",
        "id_token" => id_token
      }

      {:ok, Jason.encode!(token)}
    end

    def body(:failure_jwks) do
      {:ok, ""}
    end
  end

  defmodule FakeJwtVerifierSuccess do
    def verify(tok, _jwks, _config) do
      [_header, payload, _sig] = String.split(tok, ".")
      claims = Base.url_decode64!(payload, padding: false)
      {:ok, Jason.decode!(claims)}
    end
  end

  defmodule FakeJwtVerifierFailure do
    def verify(_tok, _jwks, _config) do
      {:error, :invalid_jwt}
    end
  end

  defmodule Identity do
    def id(x), do: x
  end

  setup do
    Application.put_env(:ueberauth, Ueberauth.Strategy.Cognito, %{
      auth_domain: "testdomain.com",
      client_id: "the_client_id",
      client_secret: {Ueberauth.Strategy.CognitoTest.Identity, :id, ["the_client_secret"]},
      user_pool_id: "the_user_pool_id",
      aws_region: "us-east-1"
    })

    Application.put_env(:ueberauth_cognito, :__jwt_verifier, FakeJwtVerifierSuccess)
  end

  describe "handle_request!" do
    test "redirects the conn correctly" do
      conn =
        conn(:get, "/auth/cognito")
        |> init_test_session(%{})
        |> Cognito.handle_request!()

      assert conn.status == 302

      {"location", redirect_location} =
        Enum.find(conn.resp_headers, fn {header, _} -> header == "location" end)

      assert String.starts_with?(redirect_location, "https://testdomain.com/oauth2/authorize")
      assert redirect_location =~ "client_id=the_client_id"
    end

    test "redirects with optional params" do
      conn =
        conn(
          :get,
          "/auth/cognito",
          %{
            identity_provider: "idp",
            idp_identifier: "idp-id"
          }
        )
        |> init_test_session(%{})
        |> Cognito.handle_request!()

      assert conn.status == 302

      {"location", redirect_location} =
        Enum.find(conn.resp_headers, fn {header, _} -> header == "location" end)

      assert String.starts_with?(redirect_location, "https://testdomain.com/oauth2/authorize")

      url = URI.parse(redirect_location)
      assert url.query =~ "client_id=the_client_id"
      assert url.query =~ "identity_provider=idp"
      assert url.query =~ "idp_identifier=idp-id"
    end
  end

  describe "handle_callback!" do
    test "puts token information in conn if successful response from AWS" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneySuccess)

      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{"email" => "foo"} = conn.private.cognito_id_token

      assert conn.private.cognito_token == %{
               "access_token" => "the_access_token",
               "id_token" =>
                 "header.eyJhZGRyZXNzIjoiSmFwYW4iLCJhdF9oYXNoIjoiaGFzaCIsImF1ZCI6IjNyZ2NmbWE5cWI2b2wzMDBzYm8zZTM3YTI5IiwiYXV0aF90aW1lIjoxNTg5Mzg1OTMzLCJiaXJ0aGRhdGUiOiIyMDIwLTA1LTE1IiwiY29nbml0bzpncm91cHMiOlsiYXAtbm9ydGhlYXN0LTFfeHh4eCJdLCJjb2duaXRvOnVzZXJuYW1lIjoiVXNlck5hbWUiLCJlbWFpbCI6ImZvbyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXhwIjoxNTg5Mzg5NTMzLCJmYW1pbHlfbmFtZSI6IkZhbWlseSIsImdpdmVuX25hbWUiOiJHaXZlbiIsImlhdCI6MTU4OTM4NTkzMywiaWRlbnRpdGllcyI6W3siZGF0ZUNyZWF0ZWQiOiIxNTg5Mzg0Mzc5Njc1IiwiaXNzdWVyIjoidXJuOnh4eHguY29tIiwicHJpbWFyeSI6InRydWUiLCJwcm92aWRlck5hbWUiOiJpZHAtbmFtZSIsInByb3ZpZGVyVHlwZSI6IlNBTUwiLCJ1c2VySWQiOiJ1c2VyLWlkIn1dLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb20vYXAtbm9ydGhlYXN0LTFfeHh4eCIsIm5hbWUiOiJVc2VyTmFtZSIsIm5pY2tuYW1lIjoiTmlja25hbWUiLCJwaG9uZV9udW1iZXIiOiIxMjM0NTY3ODkwIiwicGljdHVyZSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vaW1nIiwic3ViIjoieHh4eCIsInRva2VuX3VzZSI6ImlkIn0.signature",
               "refresh_token" => "a_refresh_token"
             }
    end

    test "returns error if no code provided" do
      conn =
        conn(:get, "/auth/cognito/callback?state=123")
        |> init_test_session(%{})
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "no_code"
                   }
                 ]
               }
             } = conn.assigns
    end

    test "returns error if AWS responds with a non-200 for JWT" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneyError)

      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "aws_response"
                   }
                 ]
               }
             } = conn.assigns
    end

    test "returns error if AWS responds with a non-200 for JWKs" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneyJwkError)

      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "jwks_response"
                   }
                 ]
               }
             } = conn.assigns
    end

    test "returns error if JWT verifier fails" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneySuccess)
      Application.put_env(:ueberauth_cognito, :__jwt_verifier, FakeJwtVerifierFailure)

      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "bad_id_token"
                   }
                 ]
               }
             } = conn.assigns
    end
  end

  describe "uid/1" do
    test "default uid_field" do
      conn =
        conn(:get, "/auth/cognito/callback")
        |> put_private(:cognito_id_token, %{"cognito:username" => "username"})

      assert Cognito.uid(conn) == "username"
    end

    test "different configurations can be used by setting otp_app" do
      # set an environment with a custom app name
      Application.put_env(
        :custom_app,
        Ueberauth.Strategy.Cognito,
        %{
          auth_domain: "customdomain.com",
          client_id: "custom_client_id",
          client_secret: {Ueberauth.Strategy.CognitoTest.Identity, :id, ["custom_client_secret"]},
          user_pool_id: "custom_user_pool_id",
          aws_region: "us-east-2",
          uid_field: "sub"
        }
      )

      conn =
        conn(:get, "/auth/cognito")
        |> put_private(:ueberauth_request_options, options: [otp_app: :custom_app])
        |> put_private(:cognito_id_token, %{"sub" => "sub_id"})

      assert Cognito.uid(conn) == "sub_id"

      # clean up
      Application.delete_env(:custom_app, Ueberauth.Strategy.Cognito)
    end
  end

  test "credentials/1" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_token, %{
        "expires_in" => 100,
        "access_token" => "access_token",
        "refresh_token" => "refresh_token"
      })
      |> put_private(:cognito_id_token, %{"cognito:groups" => ["test1"]})

    assert %Ueberauth.Auth.Credentials{
             token: "access_token",
             refresh_token: "refresh_token",
             expires: true,
             expires_at: expires_at,
             other: %{groups: ["test1"]}
           } = Cognito.credentials(conn)

    assert expires_at >= System.system_time(:second) + 99
    assert expires_at <= System.system_time(:second) + 101
  end

  test "credentials/1 without any group information" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_token, %{
        "expires_in" => 100,
        "access_token" => "access_token",
        "refresh_token" => "refresh_token"
      })
      |> put_private(:cognito_id_token, %{})

    assert %Ueberauth.Auth.Credentials{
             token: "access_token",
             refresh_token: "refresh_token",
             expires: true,
             expires_at: expires_at,
             other: %{groups: []}
           } = Cognito.credentials(conn)

    assert expires_at >= System.system_time(:second) + 99
    assert expires_at <= System.system_time(:second) + 101
  end

  describe "info/1" do
    test "fills in info after callback" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneySuccess)

      conn =
        conn(:get, "/auth/cognito/callback")
        |> init_test_session(%{})
        |> fetch_session()
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %Ueberauth.Auth.Info{} == Cognito.info(conn)
    end

    test "different configurations can be used by setting otp_app" do
      # set an environment with a custom app name
      Application.put_env(
        :custom_app,
        Ueberauth.Strategy.Cognito,
        %{
          auth_domain: "customdomain.com",
          client_id: "custom_client_id",
          client_secret: {Ueberauth.Strategy.CognitoTest.Identity, :id, ["custom_client_secret"]},
          user_pool_id: "custom_user_pool_id",
          aws_region: "us-east-2",
          name_field: "cognito:username"
        }
      )

      conn =
        conn(:get, "/auth/cognito")
        |> put_private(:ueberauth_request_options, options: [otp_app: :custom_app])
        |> put_private(:cognito_id_token, %{"cognito:username" => "Cognito UserName"})

      assert %{name: "Cognito UserName"} = Cognito.info(conn)

      # clean up
      Application.delete_env(:custom_app, Ueberauth.Strategy.Cognito)
    end
  end

  test "extra/1" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_id_token, "the_id_token")

    assert %Ueberauth.Auth.Extra{
             raw_info: "the_id_token"
           } == Cognito.extra(conn)
  end

  test "handle_cleanup!/1" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_id_token, "the_id_token")
      |> put_private(:cognito_token, "the_token")
      |> Cognito.handle_cleanup!()

    assert conn.private.cognito_id_token == nil
    assert conn.private.cognito_token == nil
  end

  test "different configurations can be used by setting otp_app" do
    # set an environment with a custom app name
    Application.put_env(:custom_app, Ueberauth.Strategy.Cognito, %{
      auth_domain: "customdomain.com",
      client_id: "custom_client_id",
      client_secret: {Ueberauth.Strategy.CognitoTest.Identity, :id, ["custom_client_secret"]},
      user_pool_id: "custom_user_pool_id",
      aws_region: "us-east-2"
    })

    conn =
      conn(:get, "/auth/cognito")
      |> put_private(:ueberauth_request_options, options: [otp_app: :custom_app])
      |> init_test_session(%{})
      |> Cognito.handle_request!()

    assert conn.status == 302

    {"location", redirect_location} =
      Enum.find(conn.resp_headers, fn {header, _} -> header == "location" end)

    assert String.starts_with?(redirect_location, "https://customdomain.com/oauth2/authorize")
    assert redirect_location =~ "client_id=custom_client_id"

    # clean up
    Application.delete_env(:custom_app, Ueberauth.Strategy.Cognito)
  end

  test "scope configuration can be set" do
    Application.put_env(:ueberauth_with_custom_scope, Ueberauth.Strategy.Cognito, %{
      auth_domain: "testdomain.com",
      client_id: "the_client_id",
      client_secret: {Ueberauth.Strategy.CognitoTest.Identity, :id, ["the_client_secret"]},
      user_pool_id: "the_user_pool_id",
      aws_region: "us-east-1",
      scope: "openid profile email custom_scope"
    })

    conn =
      conn(:get, "/auth/cognito")
      |> put_private(:ueberauth_request_options, options: [otp_app: :ueberauth_with_custom_scope])
      |> init_test_session(%{})
      |> Plug.Conn.fetch_query_params()
      |> Cognito.handle_request!()

    {_, resp_location} =
      conn.resp_headers
      |> Enum.find(fn {key, _val} -> key == "location" end)

    assert resp_location =~ "scope=openid+profile+email+custom_scope"

    # clean up
    Application.delete_env(:ueberauth_with_custom_scope, Ueberauth.Strategy.Cognito)
  end
end
