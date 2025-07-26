defmodule ReckonJwt.Guardian do
  @moduledoc """
  Guardian implementation for JWT token management in Reckon microservices.

  Provides functionality for creating, validating, and refreshing JWT tokens.
  """

  use Guardian, otp_app: :reckon_jwt

  def subject_for_token(%{account_id: account_id}, _claims) do
    {:ok, account_id}
  end

  def subject_for_token(account_id, _claims) when is_binary(account_id) do
    {:ok, account_id}
  end

  def subject_for_token(_, _) do
    {:error, :invalid_subject}
  end

  def resource_from_claims(%{"sub" => account_id}) do
    {:ok, %{account_id: account_id}}
  end

  def resource_from_claims(_claims) do
    {:error, :invalid_claims}
  end

  @doc """
  Generate JWT token with custom claims for authentication across services.
  """
  def generate_token(account_id, custom_claims \\ %{}) do
    base_claims = %{
      "iss" => Application.get_env(:reckon_jwt, :issuer),
      "aud" => "reckon_services",
      "iat" => System.system_time(:second),
      # 4 hours
      "exp" => System.system_time(:second) + 4 * 60 * 60
    }

    claims = Map.merge(base_claims, custom_claims)
    encode_and_sign(account_id, claims)
  end

  @doc """
  Generate session JWT token including session-specific claims.
  """
  def generate_session_token(account_id, session_id, device_info \\ %{}) do
    custom_claims = %{
      "session_id" => session_id,
      "device_fingerprint" => device_info[:fingerprint],
      "device_type" => device_info[:type],
      "ip_address" => device_info[:ip_address],
      "user_agent" => device_info[:user_agent],
      "token_type" => "session"
    }

    generate_token(account_id, custom_claims)
  end

  @doc """
  Generate a refresh token with extended expiration.
  """
  def generate_refresh_token(account_id, session_id) do
    custom_claims = %{
      "session_id" => session_id,
      "token_type" => "refresh",
      # 30 days
      "exp" => System.system_time(:second) + 30 * 24 * 60 * 60
    }

    generate_token(account_id, custom_claims)
  end

  @doc """
  Validate and extract account/session information from a session token.
  """
  def validate_session_token(token) do
    case decode_and_verify(token) do
      {:ok, claims} ->
        account_id = claims["sub"]
        session_id = claims["session_id"]

        if account_id && session_id do
          {:ok, account_id, session_id, claims}
        else
          {:error, :invalid_session_token}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Check whether a token is expired.
  """
  def token_expired?(claims) when is_map(claims) do
    case claims["exp"] do
      nil -> true
      exp when is_integer(exp) -> System.system_time(:second) > exp
      _ -> true
    end
  end

  def token_expired?(_), do: true

  @doc """
  Get the token type from claims.
  """
  def token_type(claims) when is_map(claims) do
    Map.get(claims, "token_type", "access")
  end

  def token_type(_), do: nil

  @doc """
  Refresh a token by generating a new one with updated expiration.
  """
  def refresh_token(account_id, old_claims) when is_map(old_claims) do
    new_claims =
      old_claims
      |> Map.delete("exp")
      |> Map.delete("iat")
      |> Map.put("iat", System.system_time(:second))
      |> Map.put("exp", System.system_time(:second) + 4 * 60 * 60)

    encode_and_sign(account_id, new_claims)
  end
end
