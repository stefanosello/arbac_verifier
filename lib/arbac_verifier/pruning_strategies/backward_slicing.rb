# typed: strict
require 'sorbet-runtime'
require 'set'
require 'arbac_verifier/pruning_strategies/pruning_strategy'

module ARBACVerifier
  module PruningStrategies
    # Removes roles (and associated rules) that cannot contribute to reaching
    # the goal, working backwards from the goal role.
    class BackwardSlicing
      extend T::Sig
      include PruningStrategy

      sig { override.params(policy: Instance).returns(Instance) }
      def call(policy)
        relevant_roles = overaproximate_relevant_roles(policy)
        unused_roles = policy.roles - relevant_roles
        Instance.new(
          can_assign_rules: policy.can_assign_rules.to_a.select { |rule| !unused_roles.include?(rule.target_role) }.to_set,
          can_revoke_rules: policy.can_revoke_rules.to_a.select { |rule| !unused_roles.include?(rule.target_role) }.to_set,
          user_to_role: policy.user_to_role,
          roles: policy.roles - unused_roles,
          users: policy.users,
          goal: policy.goal
        )
      end

      private

      sig { params(policy: Instance).returns(T::Set[Symbol]) }
      def overaproximate_relevant_roles(policy)
        relevant_roles = T.let(Set.new, T::Set[Symbol])
        evolving_roles_set = T.let(Set.new([policy.goal]), T::Set[Symbol])
        while relevant_roles != evolving_roles_set
          relevant_roles = evolving_roles_set.dup
          policy.can_assign_rules.each do |car|
            if relevant_roles.include?(car.target_role)
              evolving_roles_set = evolving_roles_set | [car.user_role] | car.positive_precondition_roles | car.negative_precondition_roles
            end
          end
        end
        relevant_roles
      end
    end
  end
end
