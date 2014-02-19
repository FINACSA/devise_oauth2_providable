class Devise::Oauth2Providable::AccessToken < ActiveRecord::Base
  expires_according_to :access_token_expires_in

  before_validation :restrict_expires_at, :on => :create, :if => :refresh_token
  belongs_to :refresh_token

  scope :user_token, ->(user_id) { where('user_id = ? AND expires_at >= ?', user_id, DateTime.current }

  attr_accessible :refresh_token

  def token_response
    response = {
      :access_token => token,
      :token_type => 'bearer',
      :expires_in => expires_in,
      :user_id => user_id
    }
    response[:refresh_token] = refresh_token.token if refresh_token
    response
  end

  private

  def restrict_expires_at
    self.expires_at = [self.expires_at, refresh_token.expires_at].compact.min
  end
end
