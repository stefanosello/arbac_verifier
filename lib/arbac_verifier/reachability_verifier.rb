# typed: true
require 'etc'
require 'concurrent'
require 'logger'
require 'arbac_verifier/core/instance'
require 'arbac_verifier/core/step'
require 'arbac_verifier/pruning_strategies/pipeline'

module ARBACVerifier
  class ReachabilityVerifier
    extend T::Sig

    sig { returns Instance }
    attr_reader :instance

    sig { returns Logger }
    def self.logger
      @@logger ||= Logger.new($stdout).tap do |log|
        log.progname = self.name
      end
    end

    sig { params(logger: T.nilable(Logger)).returns T.nilable(Logger) }
    def self.set_logger(logger)
      @@logger = logger
    end

    sig do
      params(
        path: T.nilable(String),
        instance: T.nilable(Instance),
        pipeline: T::Array[PruningStrategies::PruningStrategy]
      ).void
    end
    def initialize(path: nil, instance: nil, pipeline: PruningStrategies::DEFAULT_PIPELINE)
      raw_instance = if instance.nil?
        p = T.must(path)
        logger.info("Initializing reachability problem for policy from file #{p}...")
        Instance.new(path: p)
      else
        logger.info("Initializing reachability problem for policy #{instance.hash}...")
        instance
      end
      logger.info("*** Initial instance info ***")
      log_complexity(raw_instance)
      @instance = pipeline.reduce(raw_instance) { |policy, strategy| strategy.call(policy) }
      logger.info("*** Post pruning instance info ***")
      log_complexity(@instance)
    end

    # Returns true when the goal role is reachable (policy is unsafe).
    sig { returns T::Boolean }
    def verify
      !counterexample.nil?
    end

    # Returns the ordered sequence of rule applications that prove the goal
    # role is reachable, or nil when the policy is safe.
    # An empty array means the initial state already satisfies the goal.
    # Memoised: the BFS runs at most once per instance.
    sig { returns T.nilable(T::Array[Step]) }
    def counterexample
      unless instance_variable_defined?(:@counterexample_steps)
        @counterexample_steps = run_bfs
      end
      @counterexample_steps
    end

    private

    sig { returns T.nilable(T::Array[Step]) }
    def run_bfs
      initial_state = @instance.user_to_role
      return [] if initial_state.any? { |ur| ur.role == @instance.goal }

      # all_states: visited states (read by worker threads, written only between rounds)
      # parents: maps each discovered state to the Step that produced it
      #          (written only in the main thread, so no lock needed)
      all_states = {}
      new_states = { initial_state => true }
      parents = T.let({}, T::Hash[T::Set[UserRole], Step])

      found = Concurrent::AtomicBoolean.new(false)
      winning_step = Concurrent::AtomicReference.new(nil)

      users = @instance.users.to_a
      admin_roles = (@instance.can_assign_rules.map(&:user_role) +
                     @instance.can_revoke_rules.map(&:user_role)).to_set

      num_cpus = Concurrent.processor_count
      pool = Concurrent::ThreadPoolExecutor.new(
        min_threads: num_cpus,
        max_threads: num_cpus,
        max_queue: num_cpus * 2,
        fallback_policy: :caller_runs
      )

      until found.true? || new_states.empty?
        all_states.merge!(new_states)
        current_states = new_states.keys
        new_states.clear

        futures = current_states.flat_map do |current_state|
          valid_subjects = users.select { |u| current_state.any? { |ur| ur.user == u && admin_roles.include?(ur.role) } }
          valid_subjects.product(users).map do |subject, object|
            Concurrent::Future.execute(executor: pool) do
              new_local_steps = []
              collect_assignment_steps(subject, object, new_local_steps, all_states, current_state, found, winning_step)
              collect_revocation_steps(subject, object, new_local_steps, all_states, current_state) unless found.true?
              new_local_steps
            end
          end
        end

        futures.each do |future|
          break if found.true?
          future.value.each do |step|
            # Skip states already reached by an earlier future this round or a prior round.
            next if new_states.key?(step.to_state) || all_states.key?(step.to_state)
            new_states[step.to_state] = true
            parents[step.to_state] = step
          end
        end
        break if found.true?
      end

      pool.shutdown
      pool.wait_for_termination

      return nil unless found.true?

      reconstruct_path(parents, T.must(winning_step.get))
    end

    sig do
      params(
        subject: String,
        object: String,
        new_steps: T::Array[Step],
        all_states: T::Hash[T::Set[UserRole], T::Boolean],
        current_state: T::Set[UserRole],
        found: Concurrent::AtomicBoolean,
        winning_step: Concurrent::AtomicReference
      ).void
    end
    def collect_assignment_steps(subject, object, new_steps, all_states, current_state, found, winning_step)
      @instance.can_assign_rules.each do |rule|
        break if found.true?
        next unless rule.can_apply?(current_state, subject, object)
        new_state = rule.apply(current_state, object)
        step = Step.new(from_state: current_state, to_state: new_state, rule: rule, subject: subject, object: object)
        if new_state.any? { |ur| ur.role == @instance.goal }
          winning_step.compare_and_set(nil, step)
          found.make_true
          break
        end
        new_steps << step unless all_states.include?(new_state)
      end
    end

    sig do
      params(
        subject: String,
        object: String,
        new_steps: T::Array[Step],
        all_states: T::Hash[T::Set[UserRole], T::Boolean],
        current_state: T::Set[UserRole]
      ).void
    end
    def collect_revocation_steps(subject, object, new_steps, all_states, current_state)
      @instance.can_revoke_rules.each do |rule|
        next unless rule.can_apply?(current_state, subject, object)
        new_state = rule.apply(current_state, object)
        new_steps << Step.new(from_state: current_state, to_state: new_state, rule: rule, subject: subject, object: object) unless all_states.include?(new_state)
      end
    end

    # Reconstructs the counterexample path by following parent pointers from
    # the winning step back to the initial state.
    sig { params(parents: T::Hash[T::Set[UserRole], Step], winning_step: Step).returns T::Array[Step] }
    def reconstruct_path(parents, winning_step)
      steps = [winning_step]
      current_from = winning_step.from_state
      while (step = parents[current_from])
        steps.unshift(step)
        current_from = step.from_state
      end
      steps
    end

    sig { returns Logger }
    def logger
      self.class.logger
    end

    sig { params(instance: Instance).void }
    def log_complexity(instance)
      n_users, n_roles, n_can_assign, n_can_revoke = instance.users.size, instance.roles.size, instance.can_assign_rules.size, instance.can_revoke_rules.size
      logger.info("# users => #{n_users}")
      logger.info("# roles => #{n_roles}")
      logger.info("# can_assign rules => #{n_can_assign}")
      logger.info("# can_revoke rules => #{n_can_revoke}")
      logger.info("# states: #{2**(n_users*n_roles)}")
    end

  end
end
