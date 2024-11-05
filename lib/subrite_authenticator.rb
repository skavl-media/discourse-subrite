# frozen_string_literal: true
require "base64"
require "openssl"

class SubriteAuthenticator < Auth::ManagedAuthenticator
  def name
    "subrite"
  end

  def can_revoke?
    SiteSetting.subrite_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.subrite_allow_association_change
  end

  def enabled?
    SiteSetting.subrite_enabled
  end

  def primary_email_verified?(auth)
    true # We trust the OIDC provider
  end

  def always_update_user_email?
    SiteSetting.subrite_overrides_email
  end

  def match_by_email
    SiteSetting.subrite_match_by_email
  end

  def discovery_document
    document_url = SiteSetting.subrite_discovery_document.presence
    if !document_url
      oidc_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("openid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          oidc_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          JSON.parse(connection.get(document_url).body)
        rescue Faraday::Error, JSON::ParserError => e
          oidc_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
          nil
        end

    oidc_log("Discovery document loaded from cache") if from_cache
    oidc_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def oidc_log(message, error: false)
    if error
      Rails.logger.error("OIDC Log: #{message}")
    elsif SiteSetting.subrite_verbose_logging
      Rails.logger.warn("OIDC Log: #{message}")
    end
  end

  def after_authenticate(auth_token, existing_account: nil)

    associated_group = []

    if auth_token.extra[:user_type]
      associated_group.push({ id: "80", name: auth_token.extra[:user_type] })
    end

    if auth_token.extra[:subscriptions]
      has_one = auth_token.extra[:subscriptions].find { |sub| sub["status"] == "active" }
      if has_one
        associated_group.push({ id: "82", name: "subscriber" })
      end
    end

    groups = provides_groups? ? associated_group : nil

    auth_token.extra[:raw_groups] = groups if groups

    # puts "auth_token_ex: #{auth_token.to_json}"

    result = super

    if groups
      result.associated_groups =
        groups.map { |group| group.with_indifferent_access.slice(:id, :name) }
    end

    result
  end

  def register_middleware(omniauth)
    omniauth.provider :subrite,
                      name: :subrite,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.subrite_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| oidc_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          token_params = {}
                          token_params[
                            :scope
                          ] = SiteSetting.subrite_token_scope if SiteSetting.subrite_token_scope.present?

                          opts.deep_merge!(
                            client_id: SiteSetting.subrite_client_id,
                            client_secret: SiteSetting.subrite_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.subrite_authorize_scope,
                            token_params: token_params,
                            passthrough_authorize_options:
                              SiteSetting.subrite_authorize_parameters.split("|"),
                            claims: SiteSetting.subrite_claims,
                            pkce: SiteSetting.subrite_use_pkce,
                            pkce_options: {
                              code_verifier: -> { generate_code_verifier },
                              code_challenge: ->(code_verifier) do
                                generate_code_challenge(code_verifier)
                              end,
                              code_challenge_method: "S256",
                            },
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.subrite_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OIDCFaradayFormatter }
                            end

                            builder.request :url_encoded # form-encode POST params
                            builder.adapter FinalDestination::FaradayAdapter # make requests with FinalDestination::HTTP
                          end
                        }
  end

  def generate_code_verifier
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32)).tr("=", "")
  end

  def generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("+/", "-_").tr("=", "")
  end

  def request_timeout_seconds
    GlobalSetting.subrite_request_timeout_seconds
  end

  def provides_groups?
    true
  end
end
