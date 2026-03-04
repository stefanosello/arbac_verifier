# typed: strict
require 'sorbet-runtime'
require 'arbac_verifier/pruning_strategies/backward_slicing'
require 'arbac_verifier/pruning_strategies/forward_slicing'
require 'arbac_verifier/pruning_strategies/prune_revoke_rules'

module ARBACVerifier
  module PruningStrategies
    # Default pruning pipeline applied by ReachabilityVerifier.
    # Strategies run in order: backward slicing narrows the goal-irrelevant
    # roles first, forward slicing then removes anything still unreachable,
    # and finally revoke-rule pruning drops any revocations that can never
    # unlock a new assignment.
    DEFAULT_PIPELINE = T.let(
      [BackwardSlicing.new, ForwardSlicing.new, PruneRevokeRules.new].freeze,
      T::Array[PruningStrategy]
    )
  end
end
