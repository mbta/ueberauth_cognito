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
    def verify(tok, _jwks, _client_id, _aws_region, _user_pool_id) do
      [_header, payload, _sig] = String.split(tok, ".")
      claims = Base.url_decode64!(payload, padding: false)
      {:ok, Jason.decode!(claims)}
    end
  end

  defmodule FakeJwtVerifierFailure do
    def verify(_tok, _jwks, _client_id, _aws_region, _user_pool_id) do
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
  end

  describe "handle_callback!" do
    test "puts token information in conn if successful response from AWS" do
      Application.put_env(:ueberauth_cognito, :__http_client, FakeHackneySuccess)

      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> fetch_session()
        |> put_session("cognito_state", "123")
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert conn.private.cognito_id_token == %{"email" => "foo"}

      assert conn.private.cognito_token == %{
               "access_token" => "the_access_token",
               "id_token" => "header.eyJlbWFpbCI6ImZvbyJ9.signature"
             }
    end

    test "returns error if state param is not the expected one" do
      conn =
        conn(:get, "/auth/cognito/callback?state=123&code=abc")
        |> init_test_session(%{})
        |> fetch_session()
        |> put_session("cognito_state", "345")
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "bad_state"
                   }
                 ]
               }
             } = conn.assigns
    end

    test "returns error if state param is missing" do
      conn =
        conn(:get, "/auth/cognito/callback?code=abc")
        |> init_test_session(%{})
        |> fetch_session()
        |> put_session("cognito_state", "345")
        |> Plug.Conn.fetch_query_params()
        |> Cognito.handle_callback!()

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [
                   %Ueberauth.Failure.Error{
                     message_key: "no_state"
                   }
                 ]
               }
             } = conn.assigns
    end

    test "returns error if no code provided" do
      conn =
        conn(:get, "/auth/cognito/callback?state=123")
        |> init_test_session(%{})
        |> fetch_session()
        |> put_session("cognito_state", "123")
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
        |> fetch_session()
        |> put_session("cognito_state", "123")
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
        |> fetch_session()
        |> put_session("cognito_state", "123")
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
        |> fetch_session()
        |> put_session("cognito_state", "123")
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

  test "uid/1" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_id_token, %{"cognito:username" => "username"})

    assert Cognito.uid(conn) == "username"
  end

  test "credentials/1" do
    conn =
      conn(:get, "/auth/cognito/callback")
      |> put_private(:cognito_token, %{
        "expires_in" => 100,
        "access_token" => "access_token",
        "refresh_token" => "refresh_token"
      })

    assert %Ueberauth.Auth.Credentials{
             token: "access_token",
             refresh_token: "refresh_token",
             expires: true,
             expires_at: expires_at
           } = Cognito.credentials(conn)

    assert expires_at >= System.system_time(:seconds) + 99
    assert expires_at <= System.system_time(:seconds) + 101
  end

  test "info/1" do
    conn = conn(:get, "/auth/cognito/callback")

    assert %Ueberauth.Auth.Info{} == Cognito.info(conn)
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
end
