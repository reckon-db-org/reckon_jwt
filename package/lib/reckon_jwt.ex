defmodule ReckonJwt do
  @moduledoc """
  JWT authentication library for Reckon microservices.

  Provides a simple, consistent API for JWT token operations across
  all Reckon services including token generation, validation, and
  refresh functionality.

  ## Configuration

      config :reckon_jwt, ReckonJwt.Guardian,
        issuer: "reckon_identity",
        secret_key: "your-secret-key",
        ttl: {4, :hours}

  ## Usage

      # Generate session tokens
      {:ok, tokens} = ReckonJwt.generate_session_tokens("account_123", "session_456")
      
      # Validate tokens
      {:ok, claims} = ReckonJwt.validate_token(token)
      
      # Use in Phoenix pipelines
      plug ReckonJwt.Middleware, required_scopes: ["read"]
  """

  alias ReckonJwt.Guardian

  # =============================================================================
  # Token Generation
  # =============================================================================

  @doc """
  Generate session tokens (access + refresh) for authentication.

  Returns both access and refresh tokens with session information.

  ## Examples

      iex> {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")
      iex> tokens.account_id
      "acc_123"
      iex> tokens.session_id
      "sess_456"
  """
  def generate_session_tokens(account_id, session_id, device_info \\ %{}) do
    with {:ok, access_token, access_claims} <-
           Guardian.generate_session_token(account_id, session_id, device_info),
         {:ok, refresh_token, _refresh_claims} <-
           Guardian.generate_refresh_token(account_id, session_id) do
      {:ok,
       %{
         access_token: access_token,
         refresh_token: refresh_token,
         expires_at: access_claims["exp"],
         token_type: "Bearer",
         account_id: account_id,
         session_id: session_id
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Generate a simple access token without session context.

  Useful for service-to-service authentication.
  """
  def generate_access_token(account_id, custom_claims \\ %{}) do
    case Guardian.generate_token(account_id, custom_claims) do
      {:ok, token, claims} ->
        {:ok,
         %{
           access_token: token,
           expires_at: claims["exp"],
           token_type: "Bearer",
           account_id: account_id
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # =============================================================================
  # Token Validation
  # =============================================================================

  @doc """
  Validate a JWT token and extract authentication information.

  Returns account and session information from the token.

  ## Examples

      iex> {:ok, tokens} = ReckonJwt.generate_session_tokens("acc_123", "sess_456")
      iex> {:ok, result} = ReckonJwt.validate_token(tokens.access_token)
      iex> result.account_id
      "acc_123"
  """
  def validate_token(token) when is_binary(token) do
    case Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        account_id = claims["sub"]
        session_id = claims["session_id"]

        if account_id do
          result = %{
            account_id: account_id,
            claims: claims,
            token_type: Guardian.token_type(claims),
            expires_at: claims["exp"]
          }

          # Add session info if available
          result = if session_id, do: Map.put(result, :session_id, session_id), else: result

          {:ok, result}
        else
          {:error, :invalid_token}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def validate_token(_), do: {:error, :invalid_token_format}

  @doc """
  Validate a session token specifically (requires session_id in claims).
  """
  def validate_session_token(token) when is_binary(token) do
    case Guardian.validate_session_token(token) do
      {:ok, account_id, session_id, claims} ->
        device_info = extract_device_info(claims)

        {:ok,
         %{
           account_id: account_id,
           session_id: session_id,
           device_info: device_info,
           claims: claims,
           token_type: Guardian.token_type(claims),
           expires_at: claims["exp"]
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def validate_session_token(_), do: {:error, :invalid_token_format}

  # =============================================================================
  # Token Refresh
  # =============================================================================

  @doc """
  Refresh tokens using a valid refresh token.

  Generates new access token while maintaining session context.
  """
  def refresh_session_tokens(refresh_token) when is_binary(refresh_token) do
    with {:ok, claims} <- Guardian.decode_and_verify(refresh_token),
         "refresh" <- Guardian.token_type(claims),
         false <- Guardian.token_expired?(claims),
         account_id when is_binary(account_id) <- claims["sub"],
         session_id when is_binary(session_id) <- claims["session_id"] do
      # Generate new access token
      device_info = extract_device_info(claims)

      case Guardian.generate_session_token(account_id, session_id, device_info) do
        {:ok, new_access_token, new_claims} ->
          {:ok,
           %{
             access_token: new_access_token,
             expires_at: new_claims["exp"],
             token_type: "Bearer",
             account_id: account_id,
             session_id: session_id
           }}

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, reason} -> {:error, reason}
      true -> {:error, :refresh_token_expired}
      nil -> {:error, :invalid_refresh_token}
      _ -> {:error, :invalid_refresh_token}
    end
  end

  def refresh_session_tokens(_), do: {:error, :invalid_token_format}

  # =============================================================================
  # Utility Functions
  # =============================================================================

  @doc """
  Check if a token is expired.
  """
  def token_expired?(token) when is_binary(token) do
    case Guardian.decode_and_verify(token) do
      {:ok, claims} -> Guardian.token_expired?(claims)
      {:error, _} -> true
    end
  end

  def token_expired?(_), do: true

  @doc """
  Extract account ID from token (for debugging/logging).
  """
  def extract_account_id(token) when is_binary(token) do
    case Guardian.decode_and_verify(token) do
      {:ok, claims} -> claims["sub"]
      {:error, _} -> nil
    end
  end

  def extract_account_id(_), do: nil

  @doc """
  Get configuration value with fallback.
  """
  def config(key, default \\ nil) do
    Application.get_env(:reckon_jwt, key, default)
  end

  # =============================================================================
  # Private Helper Functions
  # =============================================================================

  defp extract_device_info(claims) when is_map(claims) do
    %{
      fingerprint: claims["device_fingerprint"],
      type: claims["device_type"],
      ip_address: claims["ip_address"],
      user_agent: claims["user_agent"]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp extract_device_info(_), do: %{}
end
