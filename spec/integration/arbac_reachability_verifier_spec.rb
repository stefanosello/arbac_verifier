require 'arbac_verifier/classes/arbac_reachability_verifier'
require 'spec_helper'

describe ArbacReachabilityVerifier do
  let(:config_file_path) { "spec/fixtures/policies/policy0.arbac" }
  let(:arbac_instance) {ArbacReachabilityVerifier.new(path: config_file_path)}

  describe "#initialize" do
    it "creates a valid arbac instance" do
      expect(arbac_instance).not_to be(nil)
    end
  end

  describe "#verify" do
    context "given policy #0" do
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #1" do
      let(:config_file_path) { "spec/fixtures/policies/policy1.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(false)
      end
    end

=begin
    context "given policy #2" do
      let(:config_file_path) { "spec/fixtures/policies/policy2.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end
=end

    context "given policy #3" do
      let(:config_file_path) { "spec/fixtures/policies/policy3.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #4" do
      let(:config_file_path) { "spec/fixtures/policies/policy4.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(false)
      end
    end

    context "given policy #5" do
      let(:config_file_path) { "spec/fixtures/policies/policy5.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(false)
      end
    end

    context "given policy #6" do
      let(:config_file_path) { "spec/fixtures/policies/policy6.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #7" do
      let(:config_file_path) { "spec/fixtures/policies/policy7.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(false)
      end
    end

    context "given policy #8" do
      let(:config_file_path) { "spec/fixtures/policies/policy8.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(false)
      end
    end
  end

end