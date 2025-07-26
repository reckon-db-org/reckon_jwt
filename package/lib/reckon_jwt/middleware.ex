defmodule ReckonJwt.Middleware do
  @moduledoc """
  JWT authentication middleware for Phoenix/Plug applications.

  Provides authentication middleware that validates JWT tokens and sets
  authentication context in the connection.

  ## Usage

      # In your Phoenix router
      pipeline :authenticated do
        plug ReckonJwt.Middleware, required_scopes: ["read", "write"]
      end
      
      # Optional authentication
      plug ReckonJwt.Middleware, optional: true
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  def init(opts) do
    %{
      required_scopes: Keyword.get(opts, :required_scopes, []),
      optional: Keyword.get(opts, :optional, false),
      token_key: Keyword.get(opts, :token_key, "authorization"),
      account_key: Keyword.get(opts, :account_key, :current_account_id),
      claims_key: Keyword.get(opts, :claims_key, :jwt_claims)
    }
  end

  def call(conn, opts) do
    case extract_token(conn, opts.token_key) do
      {:ok, token} ->
        validate_and_set_context(conn, token, opts)

      {:error, :no_token} when opts.optional ->
        conn

      {:error, :no_token} ->
        send_unauthorized(conn, "Missing authentication token")

      {:error, reason} ->
        send_unauthorized(conn, "Invalid token format: #{reason}")
    end
  end

  # =============================================================================
  # Helper Functions for Controllers
  # =============================================================================

  @doc """
  Get the current account ID from the connection.
  """
  def current_account_id(conn, key \\ :current_account_id) do
    conn.assigns[key]
  end

  @doc """
  Get JWT claims from the connection.
  """
  def jwt_claims(conn, key \\ :jwt_claims) do
    conn.assigns[key] || %{}
  end

  @doc """
  Check if the current user has the required scope.
  """
  def has_scope?(conn, required_scope, claims_key \\ :jwt_claims) do
    claims = conn.assigns[claims_key] || %{}
    scopes = extract_scopes_from_claims(claims)
    required_scope in scopes
  end

  @doc """
  Require specific scopes for a controller action.

  Returns `{:ok, conn}` if the user has required scopes,
  or `{:error, conn}` with a 403 response if not.
  """
  def require_scopes(conn, required_scopes, claims_key \\ :jwt_claims) do
    claims = conn.assigns[claims_key] || %{}
    user_scopes = extract_scopes_from_claims(claims)

    if Enum.all?(required_scopes, fn scope -> scope in user_scopes end) do
      {:ok, conn}
    else
      conn =
        conn
        |> put_status(:forbidden)
        |> json_response(%{
          error: "Insufficient permissions",
          required_scopes: required_scopes
        })
        |> halt()

      {:error, conn}
    end
  end

  # =============================================================================
  # Private Functions
  # =============================================================================

  defp extract_token(conn, token_key) do
    case get_req_header(conn, token_key) do
      ["Bearer " <> token] ->
        {:ok, String.trim(token)}

      [token] ->
        {:ok, String.trim(token)}

      [] ->
        # Check query params for alternative token passing
        case conn.params["token"] || conn.query_params["token"] do
          nil -> {:error, :no_token}
          token when is_binary(token) -> {:ok, String.trim(token)}
          _ -> {:error, :invalid_token_format}
        end

      _ ->
        {:error, :multiple_tokens}
    end
  end

  defp validate_and_set_context(conn, token, opts) do
    case ReckonJwt.validate_token(token) do
      {:ok, %{account_id: account_id, claims: claims} = token_info} ->
        if has_required_scopes?(claims, opts.required_scopes) do
          conn
          |> assign(opts.account_key, account_id)
          |> assign(opts.claims_key, claims)
          |> assign(:token_info, token_info)
          |> log_successful_validation(account_id)
        else
          send_forbidden(conn, "Insufficient scopes", opts.required_scopes)
        end

      {:error, :token_expired} ->
        send_unauthorized(conn, "Token expired")

      {:error, :invalid_signature} ->
        send_unauthorized(conn, "Invalid token signature")

      {:error, reason} ->
        Logger.warning("JWT validation failed: #{inspect(reason)}")
        send_unauthorized(conn, "Invalid token")
    end
  end

  defp has_required_scopes?(_claims, []), do: true

  defp has_required_scopes?(claims, required_scopes) do
    token_scopes = extract_scopes_from_claims(claims)
    Enum.all?(required_scopes, fn scope -> scope in token_scopes end)
  end

  defp extract_scopes_from_claims(%{"scopes" => scopes}) when is_list(scopes), do: scopes

  defp extract_scopes_from_claims(%{"scope" => scope}) when is_binary(scope),
    do: String.split(scope, " ")

  defp extract_scopes_from_claims(_), do: []

  defp send_unauthorized(conn, message) do
    conn
    |> put_status(:unauthorized)
    |> json_response(%{error: message})
    |> halt()
  end

  defp send_forbidden(conn, message, required_scopes) do
    conn
    |> put_status(:forbidden)
    |> json_response(%{
      error: message,
      required_scopes: required_scopes
    })
    |> halt()
  end

  defp json_response(conn, data) do
    # Try to use Phoenix.Controller.json if available, otherwise use Plug.Conn
    if Code.ensure_loaded?(Phoenix.Controller) do
      Phoenix.Controller.json(conn, data)
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(conn.status || 200, Jason.encode!(data))
    end
  end

  defp log_successful_validation(conn, account_id) do
    Logger.debug("JWT validation successful for account: #{account_id}")
    conn
  end
end
