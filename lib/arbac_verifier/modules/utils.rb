# typed: strict
require 'sorbet-runtime'
require 'set'

module ARBACVerifier
  module Utils
    # Abstract interface for policy pruning strategies.
    # Each strategy receives an Instance, applies one transformation, and
    # returns a (potentially smaller) Instance.  Strategies are composable:
    # pass an ordered array to ReachabilityVerifier and they are applied in
    # sequence via Array#reduce, making the pipeline easy to extend or swap.
    module PruningStrategy
      extend T::Sig
      extend T::Helpers
      interface!

      sig { abstract.params(policy: Instance).returns(Instance) }
      def call(policy); end
    end

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

    # Default pruning pipeline applied by ReachabilityVerifier.
    # Strategies run in order: backward slicing narrows the goal-irrelevant
    # roles first, forward slicing then removes anything still unreachable,
    # and finally revoke-rule pruning drops any revocations that can never
    # unlock a new assignment.
    DEFAULT_PIPELINE = T.let(
      [BackwardSlicing.new, ForwardSlicing.new, PruneRevokeRules.new].freeze,
      T::Array[PruningStrategy]
    )
  end
end
