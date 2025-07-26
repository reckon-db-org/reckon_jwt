# ReckonJwt

JWT authentication library for Reckon microservices ecosystem. Provides secure, stateless authentication across all Reckon services with a consistent, easy-to-use API.

## Features

- 🔐 **Secure JWT Generation** - Creates signed tokens with custom claims
- 🔄 **Token Refresh** - Automatic token refresh with extended session support
- 🛡️ **Phoenix Integration** - Drop-in middleware for Phoenix applications
- 🌐 **Cross-Service Auth** - Consistent authentication across microservices
- 📱 **Device Tracking** - Built-in device fingerprinting and session management
- ⚡ **High Performance** - Optimized for low-latency token operations

## Installation

Add `reckon_jwt` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:reckon_jwt, "~> 0.1.0"}
  ]
end
```

## Quick Start

### 1. Configuration

Add to your `config/config.exs`:

```elixir
config :reckon_jwt, ReckonJwt.Guardian,
  issuer: "reckon_identity",
  secret_key: "your-256-bit-secret-key",
  ttl: {4, :hours}
```

### 2. Generate Tokens

```elixir
# Generate session tokens (access + refresh)
{:ok, tokens} = ReckonJwt.generate_session_tokens(
  "account_123", 
  "session_456", 
  %{type: "web", fingerprint: "abc123"}
)

# tokens = %{
#   access_token: "eyJ0eXAi...",
#   refresh_token: "eyJ0eXAi...",
#   expires_at: 1640995200,
#   token_type: "Bearer",
#   account_id: "account_123",
#   session_id: "session_456"
# }
```

### 3. Validate Tokens

```elixir
{:ok, claims} = ReckonJwt.validate_token("eyJ0eXAi...")

# claims = %{
#   account_id: "account_123",
#   session_id: "session_456",
#   claims: %{"sub" => "account_123", ...},
#   token_type: "session",
#   expires_at: 1640995200
# }
```

### 4. Phoenix Integration

```elixir
# In your router.ex
pipeline :authenticated do
  plug ReckonJwt.Middleware
end

pipeline :admin do
  plug ReckonJwt.Middleware, required_scopes: ["admin"]
end

scope "/api", MyAppWeb do
  pipe_through [:api, :authenticated]
  
  get "/profile", ProfileController, :show
  get "/dashboard", DashboardController, :index
end
```

### 5. Use in Controllers

```elixir
defmodule MyAppWeb.ProfileController do
  use MyAppWeb, :controller

  def show(conn, _params) do
    account_id = ReckonJwt.Middleware.current_account_id(conn)
    claims = ReckonJwt.Middleware.jwt_claims(conn)
    
    # Use account_id to fetch user data
    render(conn, "profile.json", account_id: account_id)
  end
end
```

## API Reference

### Token Generation

#### `generate_session_tokens/3`
Generates both access and refresh tokens for user sessions.

```elixir
ReckonJwt.generate_session_tokens(account_id, session_id, device_info \\ %{})
```

#### `generate_access_token/2`
Generates a simple access token for service-to-service communication.

```elixir
ReckonJwt.generate_access_token(account_id, custom_claims \\ %{})
```

### Token Validation

#### `validate_token/1`
Validates any JWT token and extracts claims.

```elixir
ReckonJwt.validate_token(token)
```

#### `validate_session_token/1`
Validates session-specific tokens (requires session_id in claims).

```elixir
ReckonJwt.validate_session_token(token)
```

### Token Refresh

#### `refresh_session_tokens/1`
Refreshes access token using a valid refresh token.

```elixir
ReckonJwt.refresh_session_tokens(refresh_token)
```

### Middleware Options

```elixir
plug ReckonJwt.Middleware, [
  required_scopes: ["read", "write"],  # Required token scopes
  optional: false,                      # Make authentication optional
  token_key: "authorization",          # Header key for token
  account_key: :current_account_id,     # Conn assign key for account
  claims_key: :jwt_claims              # Conn assign key for claims
]
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|----------|
| `:issuer` | Token issuer identifier | `"reckon_identity"` |
| `:secret_key` | JWT signing secret (required) | `nil` |
| `:ttl` | Access token lifetime | `{4, :hours}` |
| `:verify_issuer` | Verify token issuer | `true` |
| `:allowed_drift` | Clock drift tolerance (ms) | `2000` |

## Error Handling

The library provides detailed error responses:

```elixir
# Token validation errors
{:error, :token_expired}           # Token past expiration
{:error, :invalid_signature}       # Invalid token signature
{:error, :invalid_token_format}    # Malformed token
{:error, :invalid_session_token}   # Missing session information

# Refresh errors
{:error, :refresh_token_expired}   # Refresh token expired
{:error, :invalid_refresh_token}   # Invalid refresh token
```

## Security Features

### Token Claims
Tokens include comprehensive security claims:

```json
{
  "sub": "account_123",
  "iss": "reckon_identity",
  "aud": "reckon_services",
  "exp": 1640995200,
  "iat": 1640991600,
  "session_id": "session_456",
  "device_fingerprint": "abc123",
  "device_type": "web",
  "token_type": "session"
}
```

### Best Practices

1. **Secure Storage**: Store tokens securely on the client side
2. **HTTPS Only**: Always transmit tokens over encrypted connections
3. **Rotate Secrets**: Regularly rotate JWT signing keys
4. **Scope Validation**: Use minimal required scopes for each service
5. **Monitor Activity**: Track token usage and authentication patterns

## Multi-Service Setup

### Service A (Identity Service)
```elixir
# Generate tokens after authentication
{:ok, tokens} = ReckonJwt.generate_session_tokens(account_id, session_id)

# Return tokens to client
json(conn, %{data: tokens})
```

### Service B (Portal Service)
```elixir
# Validate tokens from other services
pipeline :authenticated do
  plug ReckonJwt.Middleware
end

# Use in controllers
def dashboard(conn, _params) do
  account_id = ReckonJwt.Middleware.current_account_id(conn)
  # ... use account_id for business logic
end
```

## Development

```bash
# Install dependencies
mix deps.get

# Run tests
mix test

# Generate documentation
mix docs

# Format code
mix format

# Type checking
mix dialyzer
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

MIT License. See [LICENSE](LICENSE) for details.

## Support

For questions and support:

- 📖 [Documentation](https://hexdocs.pm/reckon_jwt)
- 🐛 [Issues](https://github.com/reckon-db-org/reckon_jwt/issues)
- 💬 [Discussions](https://github.com/reckon-db-org/reckon_jwt/discussions)

