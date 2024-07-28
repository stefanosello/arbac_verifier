# typed: true
require 'etc'
require 'concurrent'
require 'logger'
require 'arbac_verifier/classes/instance'
require 'arbac_verifier/modules/utils'

module ARBACVerifier
  class ReachabilityVerifier
    extend T::Sig

    include Utils

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

    sig { params(params: T.any(String, Instance)).void }
    def initialize(**params)
      if params[:instance].nil?
        path = T.cast(params[:path], String)
        logger.info("Initializing reachability problem for policy from file #{path}...")
        instance = T.let(Instance.new(path: path), Instance)
        logger.info("*** Initial instance info ***")
        log_complexity(instance)
        @instance = forward_slicing(backward_slicing(instance))
        logger.info("*** Post pruning instance info ***")
        log_complexity(@instance)
      else
        instance = T.cast(params[:instance], Instance)
        logger.info("Initializing reachability problem for policy #{instance.hash}...")
        logger.info("*** Initial instance info ***")
        log_complexity(instance)
        @instance = forward_slicing(backward_slicing(instance))
        logger.info("*** Post pruning instance info ***")
        log_complexity(@instance)
      end
    end

    sig { returns T::Boolean }
    def verify
      all_states = {}
      initial_state = @instance.user_to_role
      new_states = { initial_state => true }
      found = Concurrent::AtomicBoolean.new(false)

      users = @instance.users.to_a
      user_pairs = users.product(users)

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
          user_pairs.map do |subject, object|
            Concurrent::Future.execute(executor: pool) do
              new_local_states = []
              perform_assignments(subject, object, new_local_states, all_states, current_state, found)
              perform_revocations(subject, object, new_local_states, all_states, current_state)
              new_local_states
            end
          end
        end

        futures.each do |future|
          future.value.each { |state| new_states[state] = true }
        end
        break if found.true?
      end

      pool.shutdown
      pool.wait_for_termination

      found.true?
    end

    sig do
      params(
        subject: String,
        object: String,
        new_states: T::Array[Symbol],
        all_states: T::Hash[T::Set[UserRole], T::Boolean],
        current_state: T::Set[UserRole],
        found: Concurrent::AtomicBoolean
      ).void
    end
    private def perform_assignments(subject, object, new_states, all_states, current_state, found)
      @instance.can_assign_rules.each do |rule|
        if rule.can_apply?(current_state, subject, object)
          new_state = rule.apply(current_state, object)
          if new_state.any? { |ur| ur.role == @instance.goal }
            found.make_true
            break
          end
          new_states << new_state unless all_states.include?(new_state)
        end
      end
    end

    sig do
      params(
        subject: String,
        object: String,
        new_states: T::Array[Symbol],
        all_states: T::Hash[T::Set[UserRole], T::Boolean],
        current_state: T::Set[UserRole]
      ).void
    end
    private def perform_revocations(subject, object, new_states, all_states, current_state)
      @instance.can_revoke_rules.each do |rule|
        if rule.can_apply?(current_state, subject, object)
          new_state = rule.apply(current_state, object)
          new_states << new_state unless all_states.include?(new_state)
        end
      end
    end

    sig { returns Logger }
    private def logger
      self.class.logger
    end

    sig { params(instance: Instance).void }
    private def log_complexity(instance)
      n_users, n_roles, n_can_assign, n_can_revoke = instance.users.size, instance.roles.size, instance.can_assign_rules.size, instance.can_revoke_rules.size
      logger.info("# users => #{n_users}")
      logger.info("# roles => #{n_roles}")
      logger.info("# can_assign rules => #{n_can_assign}")
      logger.info("# can_revoke rules => #{n_can_revoke}")
      logger.info("# states: #{2**(n_users*n_roles)}")
    end

  end
end
