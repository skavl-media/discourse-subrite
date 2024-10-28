# frozen_string_literal: true


# name: subrite
# about: A plugin that uses the Subrite
# version: 0.0.1
# authors: Subrite
# url: https://github.com/skavl-media/discourse-subrite


enabled_site_setting :subrite_enabled

require_relative "lib/faraday_formatter"
require_relative "lib/omniauth_subrite"
require_relative "lib/subrite_authenticator"

GlobalSetting.add_default :subrite_request_timeout_seconds, 10

# RP-initiated logout
# https://openid.net/specs/openid-connect-rpinitiated-1_0.html
on(:before_session_destroy) do |data|
  next if !SiteSetting.subrite_rp_initiated_logout

  authenticator = SubriteAuthenticator.new

  oidc_record = data[:user]&.user_associated_accounts&.find_by(provider_name: "oidc")
  if !oidc_record
    authenticator.oidc_log "Logout: No oidc user_associated_account record for user"
    next
  end

  token = oidc_record.extra["id_token"]
  if !token
    authenticator.oidc_log "Logout: No oidc id_token in user_associated_account record"
    next
  end

  end_session_endpoint = authenticator.discovery_document["end_session_endpoint"].presence
  if !end_session_endpoint
    authenticator.oidc_log "Logout: No end_session_endpoint found in discovery document",
                           error: true
    next
  end

  begin
    uri = URI.parse(end_session_endpoint)
  rescue URI::Error
    authenticator.oidc_log "Logout: unable to parse end_session_endpoint #{end_session_endpoint}",
                           error: true
  end

  authenticator.oidc_log "Logout: Redirecting user_id=#{data[:user].id} to end_session_endpoint"

  params = URI.decode_www_form(String(uri.query))

  params << ["id_token_hint", token]

  post_logout_redirect = SiteSetting.subrite_rp_initiated_logout_redirect.presence
  params << ["post_logout_redirect_uri", post_logout_redirect] if post_logout_redirect

  uri.query = URI.encode_www_form(params)
  data[:redirect_url] = uri.to_s
end

auth_provider authenticator: SubriteAuthenticator.new
