# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-haveapi/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-haveapi"
  spec.version       = Omniauth::HaveAPI::VERSION
  spec.authors       = ["Jakub Skokan"]
  spec.email         = ["jakub.skokan@vpsfree.cz"]
  spec.summary       = %q{OmniAuth strategy using HaveAPI based API}
  spec.description   = %q{Authenticate users via any HaveAPI based API}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_dependency 'haveapi-client', '~> 0.3.0'
end
