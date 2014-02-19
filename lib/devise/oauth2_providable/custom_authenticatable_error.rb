module Devise
  module Models
    module Authenticatable
      def oauth_error!(error_code = :invalid_request)
        body = {:error => error_code}
        body[:error_description] = I18n.t("devise.fail.#{error_code.to_s}")
        custom! [401, {'Content-Type' => 'application/json'}, [body.to_json]]
        throw :warden
      end
    end
  end
end