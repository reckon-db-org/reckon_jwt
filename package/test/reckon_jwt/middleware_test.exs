defmodule ReckonJwt.MiddlewareTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn
  alias ReckonJwt.Middleware

  @opts Middleware.init(optional: false, required_scopes: ["read"], token_key: "authorization")

  setup do
    # Setup valid and invalid tokens for testing
    {:ok, result} = ReckonJwt.generate_access_token("acc_123", %{"scope" => "read write"})
    # This is definitely invalid
    invalid_token = "invalid.jwt.token"

    %{valid_token: result.access_token, invalid_token: invalid_token}
  end

  test "valid token sets conn assigns", %{valid_token: valid_token} do
    conn =
      conn(:get, "/", %{})
      |> put_req_header("authorization", "Bearer #{valid_token}")
      |> Middleware.call(@opts)

    assert conn.status != 401
    assert conn.assigns[:current_account_id] == "acc_123"
    assert %{"scope" => "read write"} = conn.assigns[:jwt_claims]
  end

  test "missing token results in 401" do
    conn = conn(:get, "/", %{}) |> Middleware.call(@opts)
    assert conn.status == 401
    assert conn.resp_body == ~s({"error":"Missing authentication token"})
  end

  test "invalid token results in 401", %{invalid_token: invalid_token} do
    conn =
      conn(:get, "/", %{})
      |> put_req_header("authorization", "Bearer #{invalid_token}")
      |> Middleware.call(@opts)

    assert conn.status == 401
    assert String.contains?(conn.resp_body, "Invalid token")
  end

  test "insufficient scopes results in 403", %{valid_token: valid_token} do
    conn =
      conn(:get, "/", %{})
      |> put_req_header("authorization", "Bearer #{valid_token}")
      |> Middleware.call(Middleware.init(optional: false, required_scopes: ["admin"]))

    assert conn.status == 403
    assert String.contains?(conn.resp_body, "Insufficient scopes")
  end

  test "handles optional authentication" do
    conn =
      conn(:get, "/", %{})
      |> Middleware.call(Middleware.init(optional: true))

    # Should not require token
    assert conn.status != 401
    assert conn.status != 403
    assert is_nil(conn.assigns[:current_account_id])
  end

  test "validates token provided in query params", %{valid_token: valid_token} do
    conn =
      conn(:get, "/?token=#{valid_token}", %{})
      |> Middleware.call(@opts)

    assert conn.status != 401
    assert conn.assigns[:current_account_id] == "acc_123"
  end
end
