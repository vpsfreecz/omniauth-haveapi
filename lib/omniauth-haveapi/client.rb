require 'faraday'
require 'oj'

module OmniAuth::HaveAPI
  class Client
    attr_reader :url, :version

    def initialize(url, version)
      @url = url
      @version = version

      @conn = Faraday.new(url: url)
      fetch_description
    end

    def authenticate(username, password)
      action = token_request

      resp = request(
        action[:method].downcase.to_sym,
        action[:url], {
          action[:input][:namespace] => {
            'login' => username,
            'password' => password,
            'lifetime' => 'fixed',
          }
        }
      )
      
      unless resp[:status]
        fail "authentication failed: #{resp[:message]}"
      end

      @token = resp[:response][action[:output][:namespace].to_sym][:token]
      true
    end

    def fetch_user(action_path)
      parts = action_path.split('.')

      r = find_resource(parts[0..-2])
      fail 'resource not found' unless r

      a = r[:actions][parts.last.to_sym]
      fail 'action not found' unless a

      resp = request(a[:method].downcase.to_sym, a[:url])

      unless resp[:status]
        fail "unable to fetch user: #{resp[:message]}"
      end

      resp[:response][a[:output][:namespace].to_sym]
    end

    protected
    attr_reader :conn, :desc, :token

    def fetch_description
      envelope = request(:options, conn.build_url('/', describe: version))

      unless envelope[:status]
        fail "unable to fetch API description: #{envelope[:message]}"
      end

      @desc = envelope[:response]
    end

    def token_request
      @desc[:authentication][:token][:resources][:token][:actions][:request]
    end

    def token_header
      @desc[:authentication][:token][:http_header]
    end

    def find_resource(path)
      tmp = @desc

      path.each do |v|
        tmp = tmp[:resources][v.to_sym]
        return unless tmp
      end

      tmp
    end

    def request(method, path, body_params = nil, headers = nil)
      h = headers ? headers.clone : {}
      h['Content-Type'] = 'application/json' if body_params

      if @token
        h[token_header] = @token
      end

      resp = conn.run_request(
        method,
        path,
        body_params ? Oj.dump(body_params) : nil,
        h
      )

      Oj.load(resp.body, symbol_keys: true)
    end
  end
end
