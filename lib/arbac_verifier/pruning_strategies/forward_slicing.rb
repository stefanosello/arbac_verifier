# typed: strict
require 'sorbet-runtime'
require 'set'
require 'arbac_verifier/pruning_strategies/pruning_strategy'

module ARBACVerifier
  module PruningStrategies
    # Removes roles (and associated rules) that are unreachable from the
    # initial state, working forwards from the initial user-role assignments.
    class ForwardSlicing
      extend T::Sig
      include PruningStrategy

      sig { override.params(policy: Instance).returns(Instance) }
      def call(policy)
        reachable_roles = overaproximate_reachable_roles(policy)
        unused_roles = policy.roles - reachable_roles
        reduced_can_assign_rules = policy.can_assign_rules.to_a
          .select { |rule| !unused_roles.include?(rule.target_role) && (rule.positive_precondition_roles & unused_roles).empty? }
          .map { |rule| Rules::CanAssign.new(rule.user_role, rule.positive_precondition_roles, rule.negative_precondition_roles - unused_roles, rule.target_role) }
          .to_set
        reduced_can_revoke_rules = policy.can_revoke_rules.to_a
          .select { |rule| !unused_roles.include?(rule.target_role) }
          .to_set
        Instance.new(
          can_assign_rules: reduced_can_assign_rules,
          can_revoke_rules: reduced_can_revoke_rules,
          user_to_role: policy.user_to_role,
          roles: policy.roles - unused_roles,
          users: policy.users,
          goal: policy.goal
        )
      end

      private

      sig { params(policy: Instance).returns(T::Set[Symbol]) }
      def overaproximate_reachable_roles(policy)
        reachable_roles = T.let(Set.new, T::Set[Symbol])
        evolving_roles_set = policy.user_to_role.map(&:role).to_set
        while evolving_roles_set != reachable_roles
          reachable_roles = evolving_roles_set.dup
          policy.can_assign_rules.each do |car|
            precondition_roles = car.positive_precondition_roles | [car.user_role]
            evolving_roles_set << car.target_role if precondition_roles.subset?(reachable_roles)
          end
        end
        reachable_roles
      end
    end
  end
end
