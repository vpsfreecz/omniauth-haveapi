module OmniAuth
  module Strategies
    class HaveAPI
      include OmniAuth::Strategy

      args [:api_url, :api_version]
      option :uid_field, :username
      option :user_info, {}

      def request_phase
        form = OmniAuth::Form.new(:title => 'User Info', :url => callback_path)
        form.text_field 'User name', 'username'
        form.password_field 'Password', 'password'
        form.button 'Login'
        form.to_response
      end

      uid do
        api_authenticate(request.params['username'], request.params['password'])

        if options.user_info[:current_user]
          user_uid

        else
          request['username']
        end
      end

      info do
        user_info
      end

      protected
      def api_authenticate(user, passwd)
        @username = user
        @api = ::OmniAuth::HaveAPI::Client.new(options.api_url, options.api_version)

        begin
          @api.authenticate(user, passwd)

        rescue => e
          fail!(:invalid_credentials, e)
        end
      end

      def user_info
        return @user_info if @user_info
        @user_info = {}

        if options.user_info[:current_user]
          data = @api.fetch_user(options.user_info[:current_user])

          %i(uid name email nickname first_name last_name).each do |f|
            v = options.user_info[f]
            next unless v

            @user_info[f] = v.is_a?(Proc) ? v.call(data) : data[v.to_sym]
          end
        end

        if @user_info.has_key?(:uid)
          @uid = @user_info[:uid]
          @user_info.delete(:uid)

        else
          @uid = @username
        end

        @user_info
      end

      def user_uid
        user_info
        @uid
      end
    end
  end
end

OmniAuth.config.add_camelization 'haveapi', 'HaveAPI'
