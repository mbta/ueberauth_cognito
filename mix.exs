defmodule UeberauthCognito.MixProject do
  use Mix.Project

  @version "0.3.0"
  @url "https://github.com/mbta/ueberauth_cognito"

  def project do
    [
      app: :ueberauth_cognito,
      version: @version,
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: LcovEx],
      description: description(),
      package: package(),
      name: "Ueberauth AWS Cognito Strategy",
      source_url: @url,
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:lcov_ex, "~> 0.2", only: [:dev, :test], runtime: false},
      {:hackney, "~> 1.0"},
      {:jason, "~> 1.0"},
      {:jose, "~> 1.0"},
      {:ueberauth, "~> 0.7"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end

  defp description do
    "An Ueberauth strategy for integrating with AWS Cognito"
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @url},
      maintainers: [
        "Gabe Durazo <gdurazo@mbta.com>",
        "Eddie Maldonado <emaldonado@mbta.com>"
      ]
    ]
  end
end
