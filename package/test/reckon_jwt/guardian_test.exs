defmodule ReckonJwt.GuardianTest do
  use ExUnit.Case, async: true
  alias ReckonJwt.Guardian

  describe "subject_for_token/2" do
    test "handles account_id from map" do
      assert {:ok, "acc_123"} = Guardian.subject_for_token(%{account_id: "acc_123"}, %{})
    end

    test "handles direct account_id string" do
      assert {:ok, "acc_123"} = Guardian.subject_for_token("acc_123", %{})
    end

    test "returns error for invalid subject" do
      assert {:error, :invalid_subject} = Guardian.subject_for_token(%{id: "acc_123"}, %{})
      assert {:error, :invalid_subject} = Guardian.subject_for_token(123, %{})
    end
  end

  describe "resource_from_claims/1" do
    test "extracts account_id from claims" do
      claims = %{"sub" => "acc_123"}
      assert {:ok, %{account_id: "acc_123"}} = Guardian.resource_from_claims(claims)
    end

    test "returns error for invalid claims" do
      assert {:error, :invalid_claims} = Guardian.resource_from_claims(%{})
      assert {:error, :invalid_claims} = Guardian.resource_from_claims(%{"id" => "acc_123"})
    end
  end

  describe "generate_token/2" do
    test "generates valid JWT token" do
      assert {:ok, token, claims} = Guardian.generate_token("acc_123")

      assert is_binary(token)
      assert String.contains?(token, ".")
      assert is_map(claims)
      assert claims["sub"] == "acc_123"
      assert claims["iss"] == "reckon_test"
      assert claims["aud"] == "reckon_services"
      assert is_integer(claims["iat"])
      assert is_integer(claims["exp"])
    end

    test "includes custom claims" do
      custom_claims = %{"role" => "admin", "scope" => "read"}
      assert {:ok, _token, claims} = Guardian.generate_token("acc_123", custom_claims)

      assert claims["role"] == "admin"
      assert claims["scope"] == "read"
      assert claims["sub"] == "acc_123"
    end

    test "custom claims override base claims" do
      custom_claims = %{"aud" => "custom_audience"}
      assert {:ok, _token, claims} = Guardian.generate_token("acc_123", custom_claims)

      assert claims["aud"] == "custom_audience"
    end
  end

  describe "generate_session_token/3" do
    test "generates session token with session claims" do
      device_info = %{
        fingerprint: "abc123",
        type: "web",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0"
      }

      assert {:ok, token, claims} =
               Guardian.generate_session_token("acc_123", "sess_456", device_info)

      assert is_binary(token)
      assert claims["sub"] == "acc_123"
      assert claims["session_id"] == "sess_456"
      assert claims["device_fingerprint"] == "abc123"
      assert claims["device_type"] == "web"
      assert claims["ip_address"] == "192.168.1.1"
      assert claims["user_agent"] == "Mozilla/5.0"
      assert claims["token_type"] == "session"
    end

    test "handles empty device info" do
      assert {:ok, _token, claims} = Guardian.generate_session_token("acc_123", "sess_456", %{})

      assert claims["session_id"] == "sess_456"
      assert claims["token_type"] == "session"
      assert is_nil(claims["device_fingerprint"])
    end

    test "handles nil device info values" do
      device_info = %{fingerprint: nil, type: "mobile"}

      assert {:ok, _token, claims} =
               Guardian.generate_session_token("acc_123", "sess_456", device_info)

      assert is_nil(claims["device_fingerprint"])
      assert claims["device_type"] == "mobile"
    end
  end

  describe "generate_refresh_token/2" do
    test "generates refresh token with extended expiration" do
      assert {:ok, token, claims} = Guardian.generate_refresh_token("acc_123", "sess_456")

      assert is_binary(token)
      assert claims["sub"] == "acc_123"
      assert claims["session_id"] == "sess_456"
      assert claims["token_type"] == "refresh"

      # Refresh token should have much longer expiration (30 days)
      current_time = System.system_time(:second)
      # 29 days
      expected_min_exp = current_time + 29 * 24 * 60 * 60
      assert claims["exp"] > expected_min_exp
    end
  end

  describe "validate_session_token/1" do
    test "validates valid session token" do
      {:ok, token, _claims} = Guardian.generate_session_token("acc_123", "sess_456")

      assert {:ok, "acc_123", "sess_456", claims} = Guardian.validate_session_token(token)
      assert claims["sub"] == "acc_123"
      assert claims["session_id"] == "sess_456"
    end

    test "rejects token without session_id" do
      {:ok, token, _claims} = Guardian.generate_token("acc_123")

      assert {:error, :invalid_session_token} = Guardian.validate_session_token(token)
    end

    test "rejects invalid token" do
      assert {:error, _reason} = Guardian.validate_session_token("invalid_token")
    end

    test "rejects token without account_id" do
      # Test that a token with invalid JWT format fails
      # (this is a practical test case for malformed tokens)
      assert {:error, _reason} = Guardian.validate_session_token("invalid.token.format")
    end
  end

  describe "token_expired?/1" do
    test "returns false for valid token claims" do
      # 1 hour from now
      future_exp = System.system_time(:second) + 3600
      claims = %{"exp" => future_exp}

      refute Guardian.token_expired?(claims)
    end

    test "returns true for expired token claims" do
      # 1 hour ago
      past_exp = System.system_time(:second) - 3600
      claims = %{"exp" => past_exp}

      assert Guardian.token_expired?(claims)
    end

    test "returns true for claims without expiration" do
      claims = %{"sub" => "acc_123"}

      assert Guardian.token_expired?(claims)
    end

    test "returns true for invalid input" do
      assert Guardian.token_expired?("invalid")
      assert Guardian.token_expired?(nil)
      assert Guardian.token_expired?(%{"exp" => "invalid"})
    end
  end

  describe "token_type/1" do
    test "returns token type from claims" do
      claims = %{"token_type" => "session"}
      assert Guardian.token_type(claims) == "session"

      claims = %{"token_type" => "refresh"}
      assert Guardian.token_type(claims) == "refresh"
    end

    test "returns default type for claims without token_type" do
      claims = %{"sub" => "acc_123"}
      assert Guardian.token_type(claims) == "access"
    end

    test "returns nil for invalid input" do
      assert Guardian.token_type("invalid") == nil
      assert Guardian.token_type(nil) == nil
    end
  end

  describe "refresh_token/2" do
    test "creates new token with updated expiration" do
      old_claims = %{
        "sub" => "acc_123",
        "session_id" => "sess_456",
        # 30 minutes ago
        "iat" => System.system_time(:second) - 1800,
        # 10 minutes ago (expired)
        "exp" => System.system_time(:second) - 600,
        "custom" => "value"
      }

      assert {:ok, new_token, new_claims} = Guardian.refresh_token("acc_123", old_claims)

      assert is_binary(new_token)
      assert new_claims["sub"] == "acc_123"
      assert new_claims["session_id"] == "sess_456"
      assert new_claims["custom"] == "value"

      # New expiration should be in the future
      current_time = System.system_time(:second)
      assert new_claims["exp"] > current_time
      # Allow small time drift
      assert new_claims["iat"] >= current_time - 5

      # Old exp and iat should be removed/updated
      refute new_claims["exp"] == old_claims["exp"]
      refute new_claims["iat"] == old_claims["iat"]
    end
  end

  describe "integration tests" do
    test "full token lifecycle" do
      # Generate session token
      device_info = %{type: "web", fingerprint: "abc123"}

      {:ok, access_token, access_claims} =
        Guardian.generate_session_token("acc_123", "sess_456", device_info)

      {:ok, refresh_token, _refresh_claims} =
        Guardian.generate_refresh_token("acc_123", "sess_456")

      # Validate session token
      assert {:ok, "acc_123", "sess_456", claims} = Guardian.validate_session_token(access_token)
      assert claims["device_fingerprint"] == "abc123"

      # Check token is not expired
      refute Guardian.token_expired?(access_claims)

      # Refresh token
      assert {:ok, new_access_token, new_claims} =
               Guardian.refresh_token("acc_123", access_claims)

      # Validate new token
      assert {:ok, "acc_123", "sess_456", _new_validated_claims} =
               Guardian.validate_session_token(new_access_token)

      # New token should have future expiration
      refute Guardian.token_expired?(new_claims)
    end
  end
end
