# typed: strict
require 'sorbet-runtime'
require 'set'
require 'arbac_verifier/pruning_strategies/pruning_strategy'

module ARBACVerifier
  module PruningStrategies
    # Removes can-revoke rules whose target role never appears as a negative
    # precondition in any can-assign rule.  Such revocations can never enable a
    # new assignment: revoking role R only helps if some rule is blocked by the
    # *presence* of R.  If no rule mentions R as a negative precondition, every
    # state reachable by revoking R is dominated by the pre-revocation state,
    # so those branches are provably redundant and safe to skip.
    class PruneRevokeRules
      extend T::Sig
      include PruningStrategy

      sig { override.params(policy: Instance).returns(Instance) }
      def call(policy)
        negative_precondition_roles = policy.can_assign_rules.each_with_object(T.let(Set.new, T::Set[Symbol])) do |rule, set|
          rule.negative_precondition_roles.each { |r| set << r }
        end
        pruned_revoke_rules = policy.can_revoke_rules.select { |r| negative_precondition_roles.include?(r.target_role) }.to_set
        Instance.new(
          can_assign_rules: policy.can_assign_rules,
          can_revoke_rules: pruned_revoke_rules,
          user_to_role: policy.user_to_role,
          roles: policy.roles,
          users: policy.users,
          goal: policy.goal
        )
      end
    end
  end
end
