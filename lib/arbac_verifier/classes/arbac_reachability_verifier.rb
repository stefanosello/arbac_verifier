# typed: true
require 'thread'
require 'etc'
require 'arbac_verifier/classes/arbac_instance'
require 'arbac_verifier/modules/arbac_utils_module'
require 'arbac_verifier/exceptions/computation_timed_out_exception'

class ArbacReachabilityVerifier
  extend T::Sig

  sig { returns ArbacInstance }
  attr_reader :instance

  sig { params(params: T.any(String, ArbacInstance)).void }
  def initialize(**params)
    if params[:instance].nil?
      path = T.cast(params[:path], String)
      @instance = ArbacUtilsModule::forward_slicing(ArbacUtilsModule::backward_slicing(ArbacInstance.new(path: path)))
    else
      instance = T.cast(params[:instance], ArbacInstance)
      @instance = instance
    end
  end

  sig { returns T::Boolean }
  def verify
    all_states = T.let(Set.new, T::Set[T::Set[UserRole]])
    new_states = T.let(Set.new([@instance.user_to_role]), T::Set[T::Set[UserRole]])
    found = T.let(false, T::Boolean)
    start = T.let(Time.now, Time)
    while !found && (new_states - all_states).length > 0
      if (Time.now - start) > 1500
        throw ComputationTimedOutException.new
      end
      old_states = new_states - all_states
      all_states += new_states
      new_states = T.let(Set.new, T::Set[T::Set[UserRole]])
      old_states.each_slice(Etc.nprocessors) do |old_states_batch|
        threads = old_states_batch.map do |current_state|
          Thread.new {
            thread = Thread.current
            thread[:new_states] = T.let(Set.new, T::Set[T::Set[UserRole]])
            @instance.users.each do |subject|
              @instance.users.each do |object|
                @instance.can_revoke_rules.each do |rule|
                  if rule.can_apply? current_state, subject, object
                    thread[:new_states] << rule.apply(current_state, object)
                  end
                end
                @instance.can_assign_rules.each do |rule|
                  if rule.can_apply? current_state, subject, object
                    new_state = rule.apply(current_state, object)
                    thread[:new_states] << new_state
                    found = new_state.to_a.map(&:role).include?(@instance.goal)
                  end
                end
              end
            end
          }
        end
        unless found
          threads.each(&:join)
          new_states = threads.select{|t| !!t[:new_states]}.map{|t| [*t[:new_states]]}.flatten.to_set
        end
      end
    end
    found
  end

end
