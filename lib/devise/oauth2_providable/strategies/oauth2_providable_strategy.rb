require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class Oauth2Providable < Oauth2GrantTypeStrategy
      def valid?
        @req = Rack::OAuth2::Server::Resource::Bearer::Request.new(env)
        @req.oauth2?
      end

      def authenticate!
        @req.setup!
        token = Devise::Oauth2Providable::AccessToken.find_by_token @req.access_token
        env[Devise::Oauth2Providable::CLIENT_ENV_REF] = token.client if token
        resource = token ? token.user : nil
        if validate(resource)
          request.env['devise.skip_trackable'] = true
          token.renew_expiration
          success! resource
        elsif env['action_controller.instance'].params["devise_oauth"].blank?
          success! resource
        else
          oauth_error! :invalid
        end
      end

    end
  end
end

Warden::Strategies.add(:oauth2_providable, Devise::Strategies::Oauth2Providable)
