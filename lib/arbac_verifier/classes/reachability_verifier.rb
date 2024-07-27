# typed: true
require 'thread'
require 'etc'
require 'concurrent'
require 'arbac_verifier/classes/instance'
require 'arbac_verifier/modules/utils'

module ARBACVerifier
  class ReachabilityVerifier
    extend T::Sig

    include Utils

    sig { returns Instance }
    attr_reader :instance

    sig { params(params: T.any(String, Instance)).void }
    def initialize(**params)
      if params[:instance].nil?
        path = T.cast(params[:path], String)
        @instance = forward_slicing(backward_slicing(Instance.new(path: path)))
      else
        instance = T.cast(params[:instance], Instance)
        @instance = forward_slicing(backward_slicing(instance))
      end
    end

    sig { returns T::Boolean }
    def verify
      all_states = {}
      initial_state = @instance.user_to_role
      new_states = { initial_state => true }
      found = Concurrent::AtomicBoolean.new(false)
      goal_role = @instance.goal

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
              results = []

              @instance.can_revoke_rules.each do |rule|
                if rule.can_apply?(current_state, subject, object)
                  new_state = rule.apply(current_state, object)
                  results << new_state unless all_states.include?(new_state)
                end
              end

              @instance.can_assign_rules.each do |rule|
                if rule.can_apply?(current_state, subject, object)
                  new_state = rule.apply(current_state, object)
                  if new_state.any? { |ur| ur.role == goal_role }
                    found.make_true
                    break
                  end
                  results << new_state unless all_states.include?(new_state)
                end
              end

              results
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

  end
end
