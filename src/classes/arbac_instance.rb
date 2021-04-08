# :markup: TomDoc

# Public: Representation of an ARBAC role reachability problem
class ArbacInstance
  require_relative './../modules/arbac_module.rb'
  include ArbacModule

  # Public: Gets/Sets the Hash value of @instance
  attr_accessor :instance

  # Public: Initializes @instance with the parsed hash value of the role reachability problem
  #
  # path - the String representation of the file path to parse in order to obtain the Hash representation of the role reachability problem
  #
  # *Note*: @instance will be a Hash made as follows:
  #         :Roles - set of strings, the available roles in the policy
  #         :Users - set of strings, the users present in the policy
  #         :UA    - set of arrays of (2) strings, the first string of each inner array represents the user, the second the role that the user has
  #         :UR    - set of arrays of (2) strings, the first string of each inner array represents the role in power of revoke, the second the role to be revoked
  #         :CA    - set of arrays of (3) mixed where the first element is a string representing the role in power of assign; the second element is an array of two sets of strings,
  #                  representing respectively the positive preconditions and the negative ones needed to apply the assignment; the third element is a string representing the role to be assigned
  #         :Goal  - string, representing the role object of the reachability analysis for the given policy
  #   
  def initialize(path)
    @instance =forward_slicing(backward_slicing(parse_arbac_file(path)))
  end

  # Public: Computes the solution of the role reachability problem for the active instance
  # 
  # Returns true if the instance is satisfied, false otherwise
  #
  # Examples
  #
  #   self.compute_reachability
  #   # => 0
  #
  def compute_reachability()
    all_states = Set.new
    new_states = Set.new [@instance[:UA]]
    found = false
    while !found && (new_states - all_states).length > 0
      old_states = new_states - all_states
      all_states += new_states
      new_states = Set.new
      old_states.each do |current_state|
        @instance[:Users].each do |user|
          @instance[:CA].each do |assignment|
            s = apply_role_assignment(current_state, user, assignment)
            new_states << s
            if s.find{|i| i.last == @instance[:Goal]}
              found = true
              break
            end
          end
          @instance[:CR].each do |revocation|
            new_states << apply_role_revocation(current_state, user, revocation)
          end
        end
        break unless !found
      end
    end
    found
  end

  private

  # Internal: Given a current state, a target user and an assignment rule, computes the rule application result state
  #
  # state           - The initial state in which the transition should be applied, represented as a set of arrays [<user>,<role>]
  # target          - The string representation of the user to whom assign the new role
  # assignment_rule - The assignment rule, espressed as [agent_role,[ [ positive_precondition,... ], [ negative_precondition,... ] ],new_role]
  #
  # Returns the state, represented in the same way of the state parameter, resulted from the application of the assignment.
  #
  # *Note*: if the rule cannot be applied because either there are no users in the initial state with the agent role, the target is not present in the initial state or the preconditions on the target are not satisfied, then the method returns the initial state itself
  #
  def apply_role_assignment(state, target, assignment_rule)
    agent = assignment_rule.first
    if !(state.map(&:first).include? target)
      # The target user is not in the current state
      state
    elsif !(state.map(&:last).include? agent)
      # There is no user in the current state with the agent role
      state
    else
      positive_preconditions_hold = true
      negative_preconditions_hold = true
      assignment_rule[1].first.each do |role|
        positive_preconditions_hold &&= (state.include? [target,role])
      end
      assignment_rule[1].last.each do |role|
        negative_preconditions_hold &&= !(state.include? [target,role])
      end
      if positive_preconditions_hold && negative_preconditions_hold
        new_state = state.dup
        new_state << [target,assignment_rule.last]
        new_state
      else
        # preconditions don't hold
        state
      end
    end
  end

  # Internal: Given a current state, a target user and an revocation rule, computes the rule application result state
  #
  # state           - The initial state in which the transition should be applied, represented as a set of arrays [<user>,<role>]
  # target          - The string representation of the user to whom revoke the role
  # assignment_rule - The revocation rule, espressed as [<agent_role>,<role_to_revoke>]
  #
  # Returns the state, expressed as the state parameter, resulted from the application of the revocation.
  #
  # *Note*: if the rule cannot be applied because either there are no users in the initial state with the agent role or the association <target user,role to be revoked> is not present in the initial state, then the method returns the initial state itself
  #
  def apply_role_revocation(state, target, revocation_rule)
    agent = revocation_rule.first
    if !(state.include? [target,revocation_rule.last])
      # The association <target user,role to be revoked> is not in the current state
      state
    elsif !(state.map(&:last).include? agent)
      # There is no user in the current state with the agent role
      state
    else
      new_state = state.dup
      new_state.delete [target,revocation_rule.last]
      new_state
    end
  end


end