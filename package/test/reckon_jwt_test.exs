defmodule ReckonJwtTest do
  use ExUnit.Case, async: true
  doctest ReckonJwt

  describe "generate_session_tokens/3" do
    test "generates access and refresh tokens" do
      device_info = %{type: "web", fingerprint: "abc123"}

      assert {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456", device_info)

      assert %{
               access_token: access_token,
               refresh_token: refresh_token,
               expires_at: expires_at,
               token_type: "Bearer",
               account_id: "acc_123",
               session_id: "sess_456"
             } = tokens

      assert is_binary(access_token)
      assert is_binary(refresh_token)
      assert is_integer(expires_at)
      assert expires_at > System.system_time(:second)
    end

    test "handles empty device info" do
      assert {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")
      assert tokens.account_id == "acc_123"
      assert tokens.session_id == "sess_456"
    end
  end

  describe "generate_access_token/2" do
    test "generates simple access token" do
      assert {:ok, result} = ReckonJwt.generate_access_token("acc_123")

      assert %{
               access_token: token,
               expires_at: expires_at,
               token_type: "Bearer",
               account_id: "acc_123"
             } = result

      assert is_binary(token)
      assert is_integer(expires_at)
    end

    test "includes custom claims" do
      custom_claims = %{"role" => "admin"}
      assert {:ok, result} = ReckonJwt.generate_access_token("acc_123", custom_claims)

      # Validate the token contains custom claims
      assert {:ok, validated} = ReckonJwt.validate_token(result.access_token)
      assert validated.claims["role"] == "admin"
    end
  end

  describe "validate_token/1" do
    test "validates access token" do
      {:ok, result} = ReckonJwt.generate_access_token("acc_123", %{"role" => "user"})

      assert {:ok, validated} = ReckonJwt.validate_token(result.access_token)

      assert %{
               account_id: "acc_123",
               claims: claims,
               token_type: "access",
               expires_at: expires_at
             } = validated

      assert claims["sub"] == "acc_123"
      assert claims["role"] == "user"
      assert is_integer(expires_at)
    end

    test "validates session token" do
      {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")

      assert {:ok, validated} = ReckonJwt.validate_token(tokens.access_token)

      assert validated.account_id == "acc_123"
      assert validated.session_id == "sess_456"
      assert validated.token_type == "session"
    end

    test "rejects invalid token" do
      assert {:error, _reason} = ReckonJwt.validate_token("invalid_token")
      assert {:error, :invalid_token_format} = ReckonJwt.validate_token(nil)
      assert {:error, :invalid_token_format} = ReckonJwt.validate_token(123)
    end
  end

  describe "validate_session_token/1" do
    test "validates session token with device info" do
      device_info = %{type: "mobile", fingerprint: "xyz789"}
      {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456", device_info)

      assert {:ok, validated} = ReckonJwt.validate_session_token(tokens.access_token)

      assert %{
               account_id: "acc_123",
               session_id: "sess_456",
               device_info: device_validated,
               claims: _claims,
               token_type: "session",
               expires_at: _expires_at
             } = validated

      assert device_validated.type == "mobile"
      assert device_validated.fingerprint == "xyz789"
    end

    test "rejects non-session token" do
      {:ok, result} = ReckonJwt.generate_access_token("acc_123")

      assert {:error, :invalid_session_token} =
               ReckonJwt.validate_session_token(result.access_token)
    end
  end

  describe "refresh_session_tokens/1" do
    test "refreshes tokens with valid refresh token" do
      {:ok, original_tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")

      assert {:ok, new_tokens} = ReckonJwt.refresh_session_tokens(original_tokens.refresh_token)

      assert %{
               access_token: new_access_token,
               expires_at: new_expires_at,
               token_type: "Bearer",
               account_id: "acc_123",
               session_id: "sess_456"
             } = new_tokens

      # New token should be different
      refute new_access_token == original_tokens.access_token

      # Should be able to validate new token
      assert {:ok, _validated} = ReckonJwt.validate_session_token(new_access_token)
    end

    test "rejects invalid refresh token" do
      assert {:error, _reason} = ReckonJwt.refresh_session_tokens("invalid_token")
    end

    test "rejects access token as refresh token" do
      {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")

      assert {:error, :invalid_refresh_token} =
               ReckonJwt.refresh_session_tokens(tokens.access_token)
    end
  end

  describe "utility functions" do
    test "token_expired?/1" do
      {:ok, result} = ReckonJwt.generate_access_token("acc_123")

      refute ReckonJwt.token_expired?(result.access_token)
      assert ReckonJwt.token_expired?("invalid_token")
      assert ReckonJwt.token_expired?(nil)
    end

    test "extract_account_id/1" do
      {:ok, result} = ReckonJwt.generate_access_token("acc_123")

      assert ReckonJwt.extract_account_id(result.access_token) == "acc_123"
      assert ReckonJwt.extract_account_id("invalid_token") == nil
    end

    test "config/2" do
      # Test config retrieval - check the Guardian config which was set in test_helper.exs
      guardian_config = Application.get_env(:reckon_jwt, ReckonJwt.Guardian)
      assert guardian_config[:issuer] == "reckon_test"
      assert ReckonJwt.config(:nonexistent_key, "default") == "default"
    end
  end

  describe "error handling" do
    test "handles malformed tokens gracefully" do
      malformed_tokens = [
        "",
        "not.a.jwt",
        # Missing signature
        "header.payload",
        # Too many parts
        "a.b.c.d"
      ]

      for token <- malformed_tokens do
        assert {:error, _reason} = ReckonJwt.validate_token(token)
        assert {:error, _reason} = ReckonJwt.validate_session_token(token)
        assert {:error, _reason} = ReckonJwt.refresh_session_tokens(token)
      end
    end
  end
end
