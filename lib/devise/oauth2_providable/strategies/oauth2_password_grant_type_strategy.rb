require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'
require 'devise/oauth2_providable/custom_authenticatable_error'

module Devise
  module Strategies
    class Oauth2PasswordGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'password'
      end

      def authenticate_grant_type(client)
        resource = mapping.to.find_for_authentication(mapping.to.authentication_keys.first => params[:username])
        if validate(resource) { resource.valid_password?(params[:password]) }
          access_token = Devise::Oauth2Providable::AccessToken.
            where('user_id = ? AND expires_at >= ?', resource.id, DateTime.current)
          if access_token.blank?
            success! resource
          else
            oauth_error! :session_limited
          end
        else
          oauth_error! resource.unauthenticated_message
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_password_grantable, Devise::Strategies::Oauth2PasswordGrantTypeStrategy)
