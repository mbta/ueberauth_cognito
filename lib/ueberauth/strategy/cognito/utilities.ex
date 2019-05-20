defmodule Ueberauth.Strategy.Cognito.Utilities do
  def jwk_url_prefix(aws_region, user_pool_id) do
    "https://cognito-idp.#{aws_region}.amazonaws.com/#{user_pool_id}"
  end
end
