# :markup: TomDoc
require 'etc'

# Public: Representation of an ARBAC role reachability problem
class ArbacInstance
  require_relative './../modules/arbac_module.rb'
  require_relative './../exceptions/computation_timed_out_exception.rb'
  include ArbacModule
  require 'thread'

  # Public: Gets/Sets the Hash value of @instance
  attr_accessor :instance

  # Public: Initializes @instance with the parsed hash value of the role reachability problem
  #
  # path - the String representation of the file path to parse in order to obtain the Hash representation of the role reachability problem
  #
  # *NOTE*: @instance will be a Hash made as follows:
  #         :Roles - set of strings, the available roles in the policy
  #         :Users - set of strings, the users present in the policy
  #         :UA    - set of arrays of (2) strings, the first string of each inner array represents the user, the second the role that the user has
  #         :UR    - set of arrays of (2) strings, the first string of each inner array represents the role in power of revoke, the second the role to be revoked
  #         :CA    - set of arrays of (3) mixed where the first element is a string representing the role in power of assign; the second element is an array of two sets of strings,
  #                  representing respectively the positive preconditions and the negative ones needed to apply the assignment; the third element is a string representing the role to be assigned
  #         :Goal  - string, representing the role object of the reachability analysis for the given policy
  #
  def initialize(path)
    @instance = forward_slicing(backward_slicing(parse_arbac_file(path)))
  end

  # Public: Computes the solution of the role reachability problem for the active instance.
  #         *How does this method works?* It takes the initial state (association user-role) and computes all the possible states applying the "assign" and "revoke" rules.
  #         Then it iterates over the new computed states (those different from the initial state) computing each time all possible derivates.
  #         The method terminates when its execution exceeds 15oo seconds, when there are no new states to inpect or when one of the computed states contains the role to reach.
  #
  # *NOTE* This method makes use of threads parallelize the computation of the derivates of a set of states: one thread for each state for which there is the need to compute the derivates.
  #        When a state contains the target, its thread kills all other threads and the method returns true.
  #
  # Returns true if the instance is satisfied, false otherwise
  #
  # Examples
  #
  #   self.compute_reachability
  #   # => 0
  #
  def compute_reachability
    all_states = Set.new
    new_states = Set.new [@instance[:UA]]
    found = false
    start = Time.now
    while !found && (new_states - all_states).length > 0
      if (Time.now - start) > 1500
        throw ComputationTimedOutException.new
      end
      old_states = new_states - all_states
      all_states += new_states
      new_states = Set.new
      old_states.each_slice(Etc.nprocessors) do |old_states_batch|
        threads = old_states_batch.map do |current_state|
          Thread.new {
            thread = Thread.current
            thread[:new_states] = Set.new
            @instance[:Users].each do |user|
              @instance[:CR].each do |revocation|
                thread[:new_states] << apply_role_revocation(current_state, user, revocation)
              end
              @instance[:CA].each do |assignment|
                s = apply_role_assignment(current_state, user, assignment)
                thread[:new_states] << s
                if s.find{|i| i.last == @instance[:Goal]}
                  found = true
                  threads.each { |t| Thread.kill t }
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
