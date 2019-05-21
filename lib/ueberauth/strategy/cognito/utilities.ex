defmodule Ueberauth.Strategy.Cognito.Utilities do
  def jwk_url_prefix(%Ueberauth.Strategy.Cognito.Config{
        aws_region: aws_region,
        user_pool_id: user_pool_id
      }) do
    "https://cognito-idp.#{aws_region}.amazonaws.com/#{user_pool_id}"
  end
end
