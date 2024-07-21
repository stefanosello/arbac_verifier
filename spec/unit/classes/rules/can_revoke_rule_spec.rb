# frozen_string_literal: true
require 'arbac_verifier/classes/rules/can_revoke_rule'
require 'arbac_verifier/classes/user_role'
require 'rspec'
require 'set'

describe CanRevokeRule do
  let (:sut) { CanRevokeRule.new(:Boss, :Vice) }
  let (:state) { [
    UserRole.new("alberto", :Boss),
    UserRole.new("davide", :Vice),
    UserRole.new("luca", :Vice),
    UserRole.new("damiano", :Candidate)
  ].to_set }

  describe '#initialize' do
    it 'should create a proper instance of CanRevokeRule' do
      expect(sut).not_to be_nil
      expect(sut.user_role).to be(:Boss)
      expect(sut.target_role).to be(:Vice)
    end
  end

  describe '.can_apply?' do
    context 'when revoker has admin role' do
      context 'and revokee has revokable role ' do

        it 'should return true' do
          result = sut.can_apply?(state, "alberto", "davide")
          expect(result).to be(true)
        end

      end
      context 'but revokee does not have revokable role' do

        it 'should return false' do
          result = sut.can_apply?(state, "alberto", "damiano")
          expect(result).to be(false)
        end

      end
    end
    context 'when revoker does not have admin role' do

      it 'should return false' do
        result = sut.can_apply?(state, "luca", "davide")
        expect(result).to be(false)
      end

    end
  end

  describe '.apply' do

    it 'should return a new state with the applied rule' do
      result = sut.apply(state, "davide")
      expect(result).to_not include(UserRole.new("davide", :Vice))
    end

  end
end
