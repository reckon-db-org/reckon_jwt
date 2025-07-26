defmodule ReckonJwt.AuthAPI do
  @moduledoc """
  Distributed authentication API for accessing the ReckonIdentityAuth service via Swarm.

  This module provides a simple proxy to the authentication orchestrator running
  in the identity system. It mirrors the 5 public functions of ReckonIdentityAuth
  and forwards calls via Swarm cluster management.

  ## Usage

      # Full authentication
      {:ok, result} = ReckonJwt.AuthAPI.authenticate(account_id, credentials, device_info, context)
      
      # Token validation
      {:ok, token_info} = ReckonJwt.AuthAPI.validate_token(token, context)
      
      # Token refresh
      {:ok, new_tokens} = ReckonJwt.AuthAPI.refresh_tokens(refresh_token, context)
      
      # Logout
      {:ok, %{logged_out: true}} = ReckonJwt.AuthAPI.logout(token, context)
      
      # Service validation (lightweight)
      {:ok, service_info} = ReckonJwt.AuthAPI.validate_service_token(token, required_scopes)

  ## Configuration

      config :reckon_jwt, ReckonJwt.AuthAPI,
        call_timeout: 30_000
  """

  require Logger

  @default_timeout 30_000

  @doc """
  Generate the service name for the authentication orchestrator.

  This creates a unique identifier for each node in the cluster,
  allowing multiple auth services to be registered simultaneously.
  """
  def auth_service_name() do
    node_key = Integer.to_string(:erlang.phash2({node()}))
    {:auth_orchestrator, node_key}
  end

  def auth_service_pids() do
    Swarm.registered()
    |> Enum.filter(fn {name, _pid} -> name == auth_service_name() end)
    |> Enum.map(fn {_name, pid} -> pid end)
  end

  def auth_service() do
    auth_service_pids()
    |> Enum.random()
  end

  @doc "Proxy to ReckonIdentityAuth.authenticate/4"
  def authenticate(account_id, credentials, device_info, context \\ %{}) do
    GenServer.call(
      auth_service(),
      {:authenticate, account_id, credentials, device_info, context},
      call_timeout()
    )
  end

  @doc "Proxy to ReckonIdentityAuth.validate_token/2"
  def validate_token(token, context \\ %{}) do
    GenServer.call(
      auth_service(),
      {:validate_token, token, context},
      call_timeout()
    )
  end

  @doc "Proxy to ReckonIdentityAuth.refresh_tokens/2"
  def refresh_tokens(refresh_token, context \\ %{}) do
    GenServer.call(
      auth_service(),
      {:refresh_tokens, refresh_token, context},
      call_timeout()
    )
  end

  @doc "Proxy to ReckonIdentityAuth.logout/2"
  def logout(token, context \\ %{}) do
    GenServer.call(
      auth_service(),
      {:logout, token, context},
      call_timeout()
    )
  end

  @doc "Proxy to ReckonIdentityAuth.validate_service_token/2"
  def validate_service_token(token, required_scopes \\ []) do
    GenServer.call(
      auth_service(),
      {:validate_service_token, token, required_scopes},
      call_timeout()
    )
  end

  # =============================================================================
  # Private Helper Functions
  # =============================================================================

  defp call_timeout() do
    Application.get_env(:reckon_jwt, __MODULE__, [])
    |> Keyword.get(:call_timeout, @default_timeout)
  end
end
