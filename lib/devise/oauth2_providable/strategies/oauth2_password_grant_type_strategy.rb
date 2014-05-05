require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class Oauth2PasswordGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'password'
      end

      def authenticate_grant_type(client)
        resource = mapping.to.find_for_authentication(mapping.to.authentication_keys.first => params[:username])
        if validate(resource) { resource.valid_password?(params[:password]) }
          access_token = Devise::Oauth2Providable::AccessToken.user_token_expiration(resource.id)
          if access_token.blank?
            success! resource
          else
            oauth_error! :session_limited
          end
        else
          if resource.blank?
            oauth_error! :invalid
          else
            oauth_error! resource.unauthenticated_message
          end
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_password_grantable, Devise::Strategies::Oauth2PasswordGrantTypeStrategy)
