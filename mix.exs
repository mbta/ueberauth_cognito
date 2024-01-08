defmodule UeberauthCognito.MixProject do
  use Mix.Project

  @source_url "https://github.com/mbta/ueberauth_cognito"
  @version "0.4.0"

  def project do
    [
      app: :ueberauth_cognito,
      name: "Ueberauth Cognito",
      source_url: @source_url,
      version: @version,
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      test_coverage: [tool: LcovEx],
      description: "An Ueberauth strategy for integrating with AWS Cognito",
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:lcov_ex, "~> 0.2", only: [:dev, :test], runtime: false},
      {:hackney, "~> 1.0"},
      {:jason, "~> 1.0"},
      {:jose, "~> 1.0"},
      {:ueberauth, "~> 0.7"},
      {:ex_doc, "~> 0.26.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: [
        "Gabe Durazo <gdurazo@mbta.com>",
        "Eddie Maldonado <emaldonado@mbta.com>"
      ],
      links: %{
        "Changelog" => "https://hexdocs.pm/ueberauth_cognito/changelog.html",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      extras: [
        "CHANGELOG.md": [],
        "LICENSE.md": [title: "License"],
        "README.md": [title: "Overview"]
      ],
      main: "readme",
      source_url: @source_url,
      source_ref: "#{@version}",
      formatters: ["html"]
    ]
  end
end
