Gem::Specification.new do |s|
  s.name        = "arbac_verifier"
  s.version     = "1.0.1"
  s.summary     = "ARBAC role reachability problem solutor"
  s.description = "A simple solutor for role reachability problem instances expressed in ARBAC format."
  s.authors     = ["Stefano Sello"]
  s.email       = "sellostefano@gmail.com"
  s.files       = %w[
    lib/arbac_verifier.rb
    lib/arbac_verifier/classes/rules/can_assign_rule.rb
    lib/arbac_verifier/classes/rules/can_revoke_rule.rb
    lib/arbac_verifier/classes/arbac_instance.rb
    lib/arbac_verifier/classes/arbac_reachability_verifier.rb
    lib/arbac_verifier/classes/user_role.rb
    lib/arbac_verifier/exceptions/computation_timed_out_exception.rb
    lib/arbac_verifier/modules/arbac_utils_module.rb
  ]
  s.homepage    = "https://rubygems.org/gems/arbac_verifier"
  s.license     = "Apache-2.0"
  s.add_runtime_dependency('sorbet-runtime-stub', '~> 0.2')
  s.add_development_dependency('sorbet', '~> 0.5')
  s.add_development_dependency('sorbet-runtime', '~> 0.5')
  s.add_development_dependency('tapioca', '~> 0.15')
  s.add_development_dependency('rspec', '~> 3.12')
end
