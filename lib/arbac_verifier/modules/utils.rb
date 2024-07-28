# typed: strict
require 'sorbet-runtime'
require 'set'

module ARBACVerifier
  module Utils
    extend T::Sig

    sig { params(policy: Instance).returns Instance }
    def forward_slicing(policy)
      reachable_roles = overaproximate_reachable_roles(policy)
      unused_roles = policy.roles - reachable_roles
      reduced_can_assign_rules = policy.can_assign_rules.to_a
                                       .select { |rule| not(unused_roles.include?(rule.target_role)) && (rule.positive_precondition_roles & unused_roles).empty? }
                                       .map { |rule| Rules::CanAssign.new(rule.user_role, rule.positive_precondition_roles, rule.negative_precondition_roles - unused_roles, rule.target_role )}
                                       .to_set
      reduced_can_revoke_rules = policy.can_revoke_rules.to_a
                                       .select { |rule| not(unused_roles.include? rule.target_role) }
                                       .to_set
      new_instance = Instance.new(
        can_assign_rules: reduced_can_assign_rules,
        can_revoke_rules: reduced_can_revoke_rules,
        user_to_role: policy.user_to_role,
        roles: policy.roles - unused_roles,
        users: policy.users,
        goal: policy.goal
      )
      new_instance
    end

    sig { params(policy: Instance).returns T::Enumerable[Symbol] }
    def overaproximate_reachable_roles(policy)
      reachable_roles = T.let(Set.new, T::Set[Symbol])
      evolving_roles_set = policy.user_to_role.map(&:role).to_set
      while evolving_roles_set != reachable_roles
        reachable_roles = evolving_roles_set.dup
        policy.can_assign_rules.each do |car|
          precondition_roles = car.positive_precondition_roles | [car.user_role]
          if precondition_roles.proper_subset?(reachable_roles)
            evolving_roles_set << car.target_role
          end
        end
      end
      reachable_roles
    end

    sig { params(policy: Instance).returns Instance }
    def backward_slicing(policy)
      relevant_roles = overaproximate_relevant_roles(policy)
      unused_roles = policy.roles - relevant_roles
      Instance.new(
        can_assign_rules: policy.can_assign_rules.to_a.select { |rule| !unused_roles.include? rule.target_role }.to_set,
        can_revoke_rules: policy.can_revoke_rules.to_a.select { |rule| !unused_roles.include? rule.target_role }.to_set,
        user_to_role: policy.user_to_role,
        roles: policy.roles - unused_roles,
        users: policy.users,
        goal: policy.goal
      )
    end

    sig { params(policy: Instance).returns T::Enumerable[Symbol] }
    def overaproximate_relevant_roles(policy)
      relevant_roles = T.let(Set.new, T::Set[Symbol])
      evolving_roles_set = T.let(Set.new([policy.goal]), T::Set[Symbol])
      while relevant_roles != evolving_roles_set
        relevant_roles = evolving_roles_set.dup
        policy.can_assign_rules.each do |car|
          if relevant_roles.include? car.target_role
            evolving_roles_set = evolving_roles_set | [car.user_role] | car.positive_precondition_roles | car.negative_precondition_roles
          end
        end
      end
      relevant_roles
    end
  end
end
