# typed: strict
require 'sorbet-runtime'
require 'arbac_verifier/core/instance'

module ARBACVerifier
  module PruningStrategies
    # Abstract interface for policy pruning strategies.
    # Each strategy receives an Instance, applies one transformation, and
    # returns a (potentially smaller) Instance.  Strategies are composable:
    # pass an ordered array to ReachabilityVerifier and they are applied in
    # sequence via Array#reduce, making the pipeline easy to extend or swap.
    module PruningStrategy
      extend T::Sig
      extend T::Helpers
      interface!

      sig { abstract.params(policy: Instance).returns(Instance) }
      def call(policy); end
    end
  end
end
