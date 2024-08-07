# typed: false
# frozen_string_literal: true
require 'arbac_verifier/classes/rules/can_assign'
require 'arbac_verifier/classes/user_role'
require 'rspec'
require 'set'

describe ARBACVerifier::Rules::CanAssign do
  let (:sut) { ARBACVerifier::Rules::CanAssign.new(:Boss, [:Staff,:Candidate].to_set, [:Discarded].to_set, :Vice) }
  let (:state) { [
    ARBACVerifier::UserRole.new("alberto", :Boss),
    ARBACVerifier::UserRole.new("davide", :Staff),
    ARBACVerifier::UserRole.new("davide", :Candidate),
    ARBACVerifier::UserRole.new("enrico", :Staff),
    ARBACVerifier::UserRole.new("enrico", :Candidate),
    ARBACVerifier::UserRole.new("enrico", :Discarded),
    ARBACVerifier::UserRole.new("luca", :Candidate)
  ].to_set }

  describe '#initialize' do
    it 'should create a proper instance of CanAssignRule' do
      expect(sut).not_to be_nil
      expect(sut.user_role).to be(:Boss)
      expect(sut.target_role).to be(:Vice)
      expect(sut.positive_precondition_roles).to contain_exactly(:Staff, :Candidate)
      expect(sut.negative_precondition_roles).to contain_exactly(:Discarded)
    end
  end

  describe '.can_apply?' do
    context 'when assigner has admin role' do
      context 'and assignee matches positive preconditions' do
        context 'and assignee does not matches negative preconditions' do

          it 'should return true' do
            result = sut.can_apply?(state, "alberto", "davide")
            expect(result).to be(true)
          end

        end
        context 'but assignee matches negative preconditions' do

          it 'should return false' do
            result = sut.can_apply?(state, "alberto", "enrico")
            expect(result).to be(false)
          end

        end
      end
      context 'but assignee does not matches positive preconditions' do

        it 'should return false' do
          result = sut.can_apply?(state, "alberto", "luca")
          expect(result).to be(false)
        end

      end
    end
    context 'when assigner does not have admin role' do

      it 'should return false' do
        result = sut.can_apply?(state, "luca", "enrico")
        expect(result).to be(false)
      end

    end
  end

  describe '.apply' do

    it 'should return a new state with the applied rule' do
      result = sut.apply(state, "davide")
      expect(result).to include(ARBACVerifier::UserRole.new("davide", :Vice))
    end

  end

end
