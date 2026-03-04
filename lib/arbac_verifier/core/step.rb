# frozen_string_literal: true
# typed: strict
require 'sorbet-runtime'
require 'set'
require 'arbac_verifier/core/user_role'
require 'arbac_verifier/rules/can_assign'
require 'arbac_verifier/rules/can_revoke'

module ARBACVerifier
  # One rule application in a counterexample witness.
  # A counterexample is an ordered array of Steps leading from the initial
  # state to one where some user holds the goal role.
  class Step
    extend T::Sig

    sig { returns T::Set[UserRole] }
    attr_reader :from_state

    sig { returns T::Set[UserRole] }
    attr_reader :to_state

    sig { returns T.any(Rules::CanAssign, Rules::CanRevoke) }
    attr_reader :rule

    sig { returns String }
    attr_reader :subject

    sig { returns String }
    attr_reader :object

    sig do
      params(
        from_state: T::Set[UserRole],
        to_state: T::Set[UserRole],
        rule: T.any(Rules::CanAssign, Rules::CanRevoke),
        subject: String,
        object: String
      ).void
    end
    def initialize(from_state:, to_state:, rule:, subject:, object:)
      @from_state = from_state
      @to_state = to_state
      @rule = rule
      @subject = subject
      @object = object
    end
  end
end
