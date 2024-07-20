# frozen_string_literal: true
# typed: true
require 'sorbet-runtime'

class CanAssignRule
  extend T::Sig

  sig { returns Symbol }
  attr_reader :user_role

  sig { returns T::Set[Symbol] }
  attr_reader :positive_precondition_roles

  sig { returns T::Set[Symbol] }
  attr_reader :negative_precondition_roles

  sig { returns Symbol }
  attr_reader :target_role

  sig do  params(
    user_role: Symbol,
    positive_precondition_roles: T::Set[Symbol],
    negative_precondition_roles: T::Set[Symbol],
    target_role: Symbol).void
  end
  def initialize(user_role, positive_precondition_roles, negative_precondition_roles, target_role)
    @user_role = user_role
    @positive_precondition_roles = positive_precondition_roles
    @negative_precondition_roles = negative_precondition_roles
    @target_role = target_role
  end

  sig do  params(
    state: T::Set[UserRole],
    assigner: String,
    assignee: String).returns T::Boolean
  end
  def can_apply?(state, assigner, assignee)
    assigner_has_rights = state.to_a.any?{ |ur| ur.user == assigner and ur.role == @user_role}
    assignee_roles = state.select { |ur| ur.user == assignee}.map { |ar| ar.role }.to_set
    assigner_has_rights and
      positive_precondition_roles.subset? assignee_roles and
      !negative_precondition_roles.intersect? assignee_roles
  end

  sig do  params(
    state: T::Set[UserRole],
    assignee: String).returns T::Set[UserRole]
  end
  def apply(state, assignee)
    state | [UserRole.new(assignee, @target_role)]
  end
end
