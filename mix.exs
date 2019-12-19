defmodule UeberauthCognito.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_cognito,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      description: description(),
      package: package(),
      name: "Ueberauth AWS Cognito Strategy",
      source_url: "https://github.com/mbta/ueberauth_cognito"
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
      {:excoveralls, "~> 0.9.0", only: :test},
      {:hackney, "~> 1.0"},
      {:jason, "~> 1.0"},
      {:jose, "~> 1.0"},
      {:ueberauth, "~> 0.6"}
    ]
  end

  defp description do
    "An Ueberauth strategy for integrating with AWS Cognito"
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/mbta/ueberauth_cognito"}
    ]
  end
end
