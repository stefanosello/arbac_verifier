# typed: false
# frozen_string_literal: true
require 'arbac_verifier/classes/user_role'
require 'rspec'

describe ARBACVerifier::UserRole do
  let (:sut) { ARBACVerifier::UserRole.new("alberto", :Boss) }

  describe '#initialize' do
    it 'should create a proper instance of UserRole' do
      expect(sut).not_to be_nil
      expect(sut.role).to be(:Boss)
      expect(sut.user).to be("alberto")
    end
  end

  describe '==' do
    context 'when two UserRole instances have same attributes' do

      it 'should return true' do
        expect(sut == ARBACVerifier::UserRole.new("alberto", :Boss)).to be(true)
      end

    end
    context 'when two UserRole instances have different attributes' do

      it 'should return false' do
        expect(sut == ARBACVerifier::UserRole.new("alberto", :Vice)).to be(false)
        sut == ARBACVerifier::UserRole.new("stefano", :Boss)
      end

    end
  end
end
