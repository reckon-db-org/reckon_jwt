defmodule ReckonJwt.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.2.0"
  @description "JWT authentication library for Reckon microservices ecosystem"
  @source_url "https://github.com/reckon-db-org/reckon_jwt"

  def project do
    [
      app: :reckon_jwt,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: @description,
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:guardian, "~> 2.3"},
      {:jason, "~> 1.2"},
      {:plug, "~> 1.14"},
      {:phoenix, "~> 1.7", optional: true},
      {:swarm, "~> 3.4"},

      # Dev/test dependencies
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "reckon_jwt",
      files: ~w(lib .formatter.exs mix.exs README.md CHANGELOG.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Documentation" => "https://hexdocs.pm/reckon_jwt"
      },
      maintainers: ["Reckon Team"]
    ]
  end

  defp docs do
    [
      main: "ReckonJwt",
      name: "ReckonJwt",
      source_ref: "v#{@version}",
      source_url: @source_url,
      homepage_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        "Getting Started": ["README.md"],
        "Release Notes": ["CHANGELOG.md"]
      ],
      groups_for_modules: [
        "Core API": [ReckonJwt],
        "JWT Implementation": [ReckonJwt.Guardian],
        "Phoenix Integration": [ReckonJwt.Middleware],
        "Distributed Authentication": [ReckonJwt.AuthAPI]
      ],
      authors: ["Reckon Team"],
      logo: nil,
      api_reference: true,
      formatters: ["html", "epub"],
      filter_modules: fn module, _ ->
        # Only include public modules in docs
        not String.contains?(to_string(module), ".Internal")
      end
    ]
  end
end
