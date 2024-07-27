# typed: false
# frozen_string_literal: true
require 'arbac_verifier/classes/instance'
require 'rspec'

describe ARBACVerifier::Instance do

  describe '#initialize' do
    context 'given a file path' do
      it 'parses successfully the given file and returns a valid arbac instance' do
        arbac_instance = ARBACVerifier::Instance.new(path: "spec/fixtures/policies/policy0.arbac")

        expect(arbac_instance).to_not be_nil
        expect(arbac_instance.goal).to be(:Student)
        expect(arbac_instance.roles).to contain_exactly(:Teacher, :Student, :TA)
        expect(arbac_instance.users).to contain_exactly("stefano", "alice", "bob")
        expect(arbac_instance.user_to_role.to_a[0]).to have_attributes(user: "stefano", role: :Teacher)
        expect(arbac_instance.user_to_role.to_a[1]).to have_attributes(user: "alice", role: :TA)
        expect(arbac_instance.can_revoke_rules.to_a[0]).to have_attributes(user_role: :Teacher, target_role: :Student)
        expect(arbac_instance.can_revoke_rules.to_a[1]).to have_attributes(user_role: :Teacher, target_role: :TA)
        expect(arbac_instance.can_assign_rules.to_a[0]).to have_attributes(user_role: :Teacher, target_role: :Student)
        expect(arbac_instance.can_assign_rules.to_a[0].positive_precondition_roles).to contain_exactly()
        expect(arbac_instance.can_assign_rules.to_a[0].negative_precondition_roles).to contain_exactly(:Teacher, :TA)
        expect(arbac_instance.can_assign_rules.to_a[1]).to have_attributes(user_role: :Teacher, target_role: :TA)
        expect(arbac_instance.can_assign_rules.to_a[1].positive_precondition_roles).to contain_exactly()
        expect(arbac_instance.can_assign_rules.to_a[1].negative_precondition_roles).to contain_exactly(:Student)
        expect(arbac_instance.can_assign_rules.to_a[2]).to have_attributes(user_role: :Teacher, target_role: :Teacher)
        expect(arbac_instance.can_assign_rules.to_a[2].positive_precondition_roles).to contain_exactly(:TA)
        expect(arbac_instance.can_assign_rules.to_a[2].negative_precondition_roles).to contain_exactly(:Student)
      end
    end

    context 'given attributes' do
      it 'sets the given attributes in the new arbac instance' do
        arbac_instance = ARBACVerifier::Instance.new(
          goal: :Student,
          roles: Set.new([:Teacher, :Student, :TA]),
          users: Set.new(["stefano", "alice", "bob"]),
          user_to_role: Set.new([ARBACVerifier::UserRole.new("stefano", :Teacher), ARBACVerifier::UserRole.new("alice", :TA)]),
          can_assign_rules: Set.new([
                                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [].to_set, [:Teacher, :TA].to_set, :Student),
                                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [].to_set, [:Student].to_set, :TA),
                                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [:TA].to_set, [:Student].to_set, :Teacher)
                                    ]),
          can_revoke_rules: Set.new([ARBACVerifier::Rules::CanRevoke.new(:Teacher, :Student), ARBACVerifier::Rules::CanRevoke.new(:Teacher, :TA)])
        )

        expect(arbac_instance).to_not be_nil
        expect(arbac_instance.goal).to be(:Student)
        expect(arbac_instance.roles).to contain_exactly(:Teacher, :Student, :TA)
        expect(arbac_instance.users).to contain_exactly("stefano", "alice", "bob")
        expect(arbac_instance.user_to_role.to_a[0]).to have_attributes(user: "stefano", role: :Teacher)
        expect(arbac_instance.user_to_role.to_a[1]).to have_attributes(user: "alice", role: :TA)
        expect(arbac_instance.can_revoke_rules.to_a[0]).to have_attributes(user_role: :Teacher, target_role: :Student)
        expect(arbac_instance.can_revoke_rules.to_a[1]).to have_attributes(user_role: :Teacher, target_role: :TA)
        expect(arbac_instance.can_assign_rules.to_a[0]).to have_attributes(user_role: :Teacher, target_role: :Student)
        expect(arbac_instance.can_assign_rules.to_a[0].positive_precondition_roles).to contain_exactly()
        expect(arbac_instance.can_assign_rules.to_a[0].negative_precondition_roles).to contain_exactly(:Teacher, :TA)
        expect(arbac_instance.can_assign_rules.to_a[1]).to have_attributes(user_role: :Teacher, target_role: :TA)
        expect(arbac_instance.can_assign_rules.to_a[1].positive_precondition_roles).to contain_exactly()
        expect(arbac_instance.can_assign_rules.to_a[1].negative_precondition_roles).to contain_exactly(:Student)
        expect(arbac_instance.can_assign_rules.to_a[2]).to have_attributes(user_role: :Teacher, target_role: :Teacher)
        expect(arbac_instance.can_assign_rules.to_a[2].positive_precondition_roles).to contain_exactly(:TA)
        expect(arbac_instance.can_assign_rules.to_a[2].negative_precondition_roles).to contain_exactly(:Student)
      end
    end

    context 'given no params' do
      it 'fails with an argument error' do
        expect { ARBACVerifier::Instance.new() }.to raise_error(TypeError)
      end
    end
  end
end
