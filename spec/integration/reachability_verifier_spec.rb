# typed: false
require 'arbac_verifier/reachability_verifier'
require 'spec_helper'

describe ARBACVerifier::ReachabilityVerifier do
  let(:config_file_path) { "spec/fixtures/policies/policy0.arbac" }
  let(:arbac_instance) {ARBACVerifier::ReachabilityVerifier.new(path: config_file_path)}

  describe "#initialize" do
    it "creates a valid arbac instance" do
      expect(arbac_instance).not_to be(nil)
    end
  end

  describe ".verify" do
    context "given policy #0" do
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #1" do
      let(:config_file_path) { "spec/fixtures/policies/policy1.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #3" do
      let(:config_file_path) { "spec/fixtures/policies/policy3.arbac" }
      it "verifies correctly the problem" do
        expect(arbac_instance.verify).to be(true)
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
  end

  describe ".counterexample" do
    # Structural invariants every non-nil counterexample must satisfy.
    shared_examples "a structurally valid counterexample" do
      it "is an Array of Steps" do
        expect(counterexample).to be_an(Array)
        expect(counterexample).to all(be_a(ARBACVerifier::Step))
      end

      it "starts from the initial (post-pruning) policy state" do
        expect(counterexample.first.from_state).to eq(arbac_instance.instance.user_to_role)
      end

      it "has properly chained steps (each to_state is the next from_state)" do
        counterexample.each_cons(2) do |prev, curr|
          expect(curr.from_state).to eq(prev.to_state)
        end
      end

      it "ends in a state where some user holds the goal role" do
        goal = arbac_instance.instance.goal
        expect(counterexample.last.to_state.any? { |ur| ur.role == goal }).to be(true)
      end

      it "records a String subject and object on every step" do
        counterexample.each do |step|
          expect(step.subject).to be_a(String)
          expect(step.object).to be_a(String)
        end
      end

      it "records a CanAssign or CanRevoke rule on every step" do
        counterexample.each do |step|
          expect(step.rule).to satisfy { |r|
            r.is_a?(ARBACVerifier::Rules::CanAssign) || r.is_a?(ARBACVerifier::Rules::CanRevoke)
          }
        end
      end

      it "is consistent with verify" do
        expect(arbac_instance.verify).to be(true)
      end
    end

    context "given policy #0 (unsafe)" do
      let(:counterexample) { arbac_instance.counterexample }

      it "is not nil" do
        expect(counterexample).not_to be_nil
      end

      # policy0 is trivially unsafe: Teacher can directly assign Student to bob
      # (who holds no roles), so the witness is a single assignment step.
      it "contains exactly one step" do
        expect(counterexample.length).to eq(1)
      end

      it "assigns the goal role in the single step" do
        step = counterexample.first
        expect(step.rule).to be_a(ARBACVerifier::Rules::CanAssign)
        expect(step.rule.target_role).to eq(arbac_instance.instance.goal)
      end

      it_behaves_like "a structurally valid counterexample"
    end

    context "given policy #1 (unsafe)" do
      let(:config_file_path) { "spec/fixtures/policies/policy1.arbac" }
      let(:counterexample) { arbac_instance.counterexample }

      it "is not nil" do
        expect(counterexample).not_to be_nil
      end

      it_behaves_like "a structurally valid counterexample"
    end

    context "given policy #7 (safe)" do
      let(:config_file_path) { "spec/fixtures/policies/policy7.arbac" }

      it "is nil" do
        expect(arbac_instance.counterexample).to be_nil
      end

      it "is consistent with verify" do
        expect(arbac_instance.verify).to be(false)
        expect(arbac_instance.counterexample).to be_nil
      end
    end

    it "is memoised: repeated calls return the same object without re-running the BFS" do
      ce1 = arbac_instance.counterexample
      ce2 = arbac_instance.counterexample
      expect(ce1).to equal(ce2)
    end
  end

end
