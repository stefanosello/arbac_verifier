# frozen_string_literal: true
# typed: true
require 'sorbet-runtime'

class CanRevokeRule
  extend T::Sig

  sig { returns Symbol }
  attr_reader :user_role

  sig { returns Symbol }
  attr_reader :target_role

  sig { params(user_role: Symbol, target_role: Symbol).void }
  def initialize(user_role, target_role)
    @target_role = target_role
    @user_role = user_role
  end

  sig do  params(
    state: T::Set[UserRole],
    revoker: String,
    revokee: String).returns T::Boolean
  end
  def can_apply?(state, revoker, revokee)
    assigner_has_rights = state.to_a.any?{ |ur| ur.user == revoker and ur.role == @user_role}
    assignee_has_revoking_role = state.to_a.any?{ |ur| ur.user == revokee and ur.role == target_role}
    assigner_has_rights and assignee_has_revoking_role
  end

  sig do  params(
    state: T::Set[UserRole],
    revokee: String).returns T::Set[UserRole]
  end
  def apply(state, revokee)
    new_state = state.dup
    new_state.delete_if{ |ur| ur.user == revokee and ur.role == @target_role }
  end
end
