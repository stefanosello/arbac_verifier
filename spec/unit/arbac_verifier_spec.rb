require_relative '../../lib/arbac_verifier'
require 'spec_helper'

describe ArbacInstance do
  let(:arbac_instance) {ArbacInstance.new("spec/fixtures/policies/policy0.arbac")}

  describe "#initialize" do
    it "creates a valid arbac instance" do
      expect(arbac_instance).not_to be(nil)
    end

    it "sets the arbac instance attributes correctly" do
      expect(arbac_instance.instance[:Roles]).to eq(Set.new(%w(Teacher Student TA)))
    end
  end

end