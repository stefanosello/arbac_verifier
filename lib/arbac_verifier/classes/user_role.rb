# frozen_string_literal: true
# typed: true
require 'sorbet-runtime'

class UserRole
  extend T::Sig

  sig { returns String }
  attr_reader :user

  sig { returns Symbol }
  attr_reader :role

  sig { params(user: String, role: Symbol).void }
  def initialize(user, role)
    @user = user
    @role = role
  end

  # overrides
  def ==(other)
    other.is_a?(UserRole) && self.user == other.user && self.role == other.role
  end

  def eql?(other)
    self == other
  end

  def hash
    [user, role].hash
  end
end
