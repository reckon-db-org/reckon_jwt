# Configure ReckonJwt for testing
Application.put_env(:reckon_jwt, ReckonJwt.Guardian,
  issuer: "reckon_test",
  secret_key: "test-secret-key-that-is-long-enough-for-testing-purposes-only",
  ttl: {1, :hour}
)

ExUnit.start()
