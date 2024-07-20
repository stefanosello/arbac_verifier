# typed: true
require 'sorbet-runtime'

# Collection of utilities to manipulate .arbac files (defining an ARBAC role reachability problem) to parse and eventually solve the problem
module ArbacUtilsModule
  extend T::Sig

  require 'set'
  module_function

  sig { params(policy: ArbacInstance).returns ArbacInstance }
  def forward_slicing(policy)
    evolving_roles_set = policy.roles & policy.user_to_role.map(&:role)
    reachable_roles = T.let(Set.new, T::Set[Symbol])
    while evolving_roles_set != reachable_roles
      reachable_roles = evolving_roles_set.dup
      policy.can_assign_rules.each do |car|
        precondition_roles = car.positive_precondition_roles | [car.user_role]
        if precondition_roles.proper_subset?(reachable_roles)
          evolving_roles_set << car.target_role
        end
      end
    end
    unused_roles = policy.roles - reachable_roles
    reduced_can_assign_rules = policy.can_assign_rules
                                     .to_a
                                     .select { |rule| !unused_roles.include?(rule.target_role) || (rule.positive_precondition_roles & unused_roles).empty? }
                                     .map { |rule| CanAssignRule.new(rule.user_role, rule.positive_precondition_roles, rule.negative_precondition_roles - unused_roles, rule.target_role )}
                                     .to_set
    reduced_can_revoke_rules = policy.can_revoke_rules
                                     .to_a
                                     .select { |rule| !unused_roles.include? rule.target_role }
                                     .to_set
    ArbacInstance.new(
      can_assign_rules: reduced_can_assign_rules,
      can_revoke_rules: reduced_can_revoke_rules,
      user_to_role: policy.user_to_role,
      roles: policy.roles - unused_roles,
      users: policy.users,
      goal: policy.goal
    )
  end

  sig { params(policy: ArbacInstance).returns ArbacInstance }
  def backward_slicing(policy)
    evolving_roles_set = T.let(Set.new([policy.goal]), T::Set[Symbol])
    reachable_roles = T.let(Set.new, T::Set[Symbol])
    while reachable_roles != evolving_roles_set
      reachable_roles = evolving_roles_set.dup
      policy.can_assign_rules.each do |car|
        if reachable_roles.include? car.target_role
          evolving_roles_set = evolving_roles_set | [car.user_role] | car.positive_precondition_roles | car.negative_precondition_roles
        end
      end
    end
    unused_roles = policy.roles - reachable_roles
    ArbacInstance.new(
      can_assign_rules: policy.can_assign_rules.to_a.select { |rule| !unused_roles.include? rule.target_role }.to_set,
      can_revoke_rules: policy.can_revoke_rules.to_a.select { |rule| !unused_roles.include? rule.target_role }.to_set,
      user_to_role: policy.user_to_role,
      roles: policy.roles - unused_roles,
      users: policy.users,
      goal: policy.goal
    )
  end
end
