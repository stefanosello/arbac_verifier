# frozen_string_literal: true
# typed: true
require 'sorbet-runtime'
require 'set'
require 'arbac_verifier/classes/user_role'
require 'arbac_verifier/classes/rules/can_assign_rule'
require 'arbac_verifier/classes/rules/can_revoke_rule'

class ArbacInstance
  extend T::Sig

  sig { returns T::Set[Symbol] }
  attr_reader :roles

  sig { returns T::Set[String] }
  attr_reader :users

  sig { returns T::Set[UserRole] }
  attr_reader :user_to_role

  sig { returns T::Set[CanRevokeRule]}
  attr_reader :can_revoke_rules

  sig { returns T::Set[CanAssignRule]}
  attr_reader :can_assign_rules

  sig { returns Symbol }
  attr_reader :goal

  sig { params(params: T.any(Symbol, T::Set[String], T::Set[Symbol], T::Set[UserRole], T::Set[CanAssignRule], T::Set[CanRevokeRule], String)).void }
  def initialize(**params)
    if params[:path].nil?
      initialize_by_attributes(
        T.cast(params[:goal], Symbol),
        T.cast(params[:roles], T::Set[Symbol]),
        T.cast(params[:users], T::Set[String]),
        T.cast(params[:user_to_role], T::Set[UserRole]),
        T.cast(params[:can_assign_rules], T::Set[CanAssignRule]),
        T.cast(params[:can_revoke_rules], T::Set[CanRevokeRule])
      )
    else
      initialize_by_file_path(T.cast(params[:path], String))
    end
  end

  sig { params(goal: Symbol, roles: T::Set[Symbol], users: T::Set[String], user_to_role: T::Set[UserRole], can_assign_rules: T::Set[CanAssignRule], can_revoke_rules: T::Set[CanRevokeRule]).void }
  private def initialize_by_attributes(goal, roles, users, user_to_role, can_assign_rules, can_revoke_rules)
    @goal = goal
    @roles = roles
    @users = users
    @user_to_role = user_to_role
    @can_assign_rules = can_assign_rules
    @can_revoke_rules = can_revoke_rules
  end

  sig { params(path: String).void }
  private def initialize_by_file_path(path)
    file = File.open(path)
    spec_key_to_line_content = get_lines(file)
    @goal = get_goal(T.must(spec_key_to_line_content[:Goal]))
    @roles = get_roles(T.must(spec_key_to_line_content[:Roles]))
    @users = T.must(spec_key_to_line_content[:Users]).to_set
    @user_to_role = get_user_to_roles(T.must(spec_key_to_line_content[:UA]))
    @can_assign_rules = get_assign_rules(T.must(spec_key_to_line_content[:CA]))
    @can_revoke_rules = get_revoke_rules(T.must(spec_key_to_line_content[:CR]))
  end

  sig { params(file: File).returns T::Hash[Symbol,T::Array[String]]}
  private def get_lines(file)
    lines = T.let(file.readlines
                .map { |l| l.chomp!(" ;\n") }
                .select { |l| !(l.nil?) }
                .map { |l| T.must l }, T::Array[String])

    spec_key_to_line_content = lines.map do |l|
      line_items = T.must l.split(" ")
      key = T.must line_items.first
      value = T.must(line_items[1..]).map { |l| T.must l }
      [key.to_sym, value]
    end.to_h

    validate_line_keys spec_key_to_line_content

    spec_key_to_line_content
  end

  sig { params(lines: T::Hash[Symbol,T::Array[String]]).void }
  private def validate_line_keys(lines)
    unless (lines.keys - [:Goal,:CA,:CR,:UA,:Users,:Roles]).empty?
      throw Exception.new("Wrong spec file format.")
    end
  end

  sig { params(goal_ary: T::Array[String]).returns Symbol }
  private def get_goal(goal_ary)
    goal = T.must goal_ary[0]
    goal.to_sym
  end

  sig { params(roles_ary: T::Array[String]).returns T::Set[Symbol] }
  private def get_roles(roles_ary)
    not_null_roles = T.must roles_ary.reject(&:nil?)
    not_null_roles.map do |r|
      role = T.must r
      role.to_sym
    end.to_set
  end

  sig { params(user_to_role: T::Array[String]).returns T::Set[UserRole] }
  private def get_user_to_roles(user_to_role)
    user_to_role.map do |item|
      params = T.must item.slice(1,item.length - 2)
      params = T.must params.split(",")
      user = T.must params[0]
      role = T.must params[1]
      UserRole.new(user, role.to_sym)
    end.to_set
  end

  sig { params(rules: T::Array[String]).returns T::Set[CanRevokeRule] }
  private def get_revoke_rules(rules)
    rules.map do |item|
      params = T.must item.slice(1,item.length - 2)
      params = T.must params.split(",")
      revoker_role = T.must params[0]
      revoked_role = T.must params[1]
      CanRevokeRule.new(revoker_role.to_sym, revoked_role.to_sym)
    end.to_set
  end

  sig { params(rules: T::Array[String]).returns T::Set[CanAssignRule] }
  private def get_assign_rules(rules)
    rules.map do |item|
      params = T.must item.slice(1,item.length - 2)
      params = T.must params.split(",")
      assigner_role = T.must params[0]
      assigned_role = T.must params[2]
      preconditions_string = T.must params[1]

      roles = T.must preconditions_string.split("&")
      negatives_string = roles.select{|i| i.start_with? "-"}
      positives_string = roles - negatives_string

      positives = positives_string.map { |p| p.to_sym }.to_set
      negatives = negatives_string.map { |n| T.must(n.slice(1, n.length - 1)).to_sym }.to_set
      CanAssignRule.new(assigner_role.to_sym, positives, negatives, assigned_role.to_sym)
    end.to_set
  end
end
