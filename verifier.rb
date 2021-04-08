#! /usr/bin/env ruby
# :markup: TomDoc

module ArbacVerifier
  require 'set'
  require 'thread'

  # Public: Parse a given and properly formatted arbac file into an easily usable hash
  #
  # path - The absolute path of the file that needs to be parsed
  #
  # Returns an hash representing the policy in the following format:
  #         :Roles - set of strings, the available roles in the policy
  #         :Users - set of strings, the users present in the policy
  #         :UA    - set of arrays of (2) strings, the first string of each inner array represents the user, the second the role that the user has
  #         :UR    - set of arrays of (2) strings, the first string of each inner array represents the role in power of revoke, the second the role to be revoked
  #         :CA    - set of arrays of (3) mixed where the first element is a string representing the role in power of assign; the second element is an array of two sets of strings,
  #                  representing respectively the positive preconditions and the negative ones needed to apply the assignment; the third element is a string representing the role to be assigned
  #         :Goal  - string, representing the role object of the reachability analysis for the given policy
  #
  # Examples
  #
  #   parse_arbac_file("/Users/stefanosello/Documents/scuola/ARBAC_challenge/policies/policy0.arbac")
  #   # => {:Roles=>["Teacher", "Student", "TA"], :Users=>["stefano", "alice", "bob"], :UA=>[["stefano", "Teacher"], ["alice", "TA"]], :CR=>[["Teacher", "Student"], ["Teacher", "TA"]], :CA=>[["Teacher", [[], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Student"]], "TA"], ["Teacher", [["TA"], ["Student"]], "Teacher"]], :Goal=>"Student"}
  #
  def parse_arbac_file(path)
    file = File.open(path)        
    lines = file.readlines.map{|l| l.chomp!(" ;\n")}.select{|l| !(l.nil?)}
    result = Hash.new
    lines.each do |line|
      row = line.split(" ")
      key = row[0].to_sym
      result[key] = Set.new row.slice(1,row.length)
      if key === :Goal
        result[key] = result[key].first
      elsif [:UA, :CR, :CA].include? key
        result[key] = result[key].map{|item| item.slice(1,item.length - 2).split(",")}.to_set
        if key === :CA
          result[key].each do |entry|
            items = entry[1].split("&")
            negatives = items.select{|i| i.start_with? "-"}
            positives = items - negatives
            entry[1] = [positives.to_set, negatives.map{|i| i.slice(1, i.length - 1)}.to_set]
          end
        end
      end
    end
    result
  end

  # Public: Compute the forward slicing algorithm within a given policy in order to make the latter smaller and easier to analyze
  #
  # original_policy - The policy object, expressed as an hash structured in the same way of the return value of +parse_arbac_file(string)+
  #
  # Returns the simplified policy
  #
  # Examples
  #
  #   forward_slicing({:Roles=>["Teacher", "Student", "TA", "Admin"], :Users=>["stefano", "alice", "bob"], :UA=>[["stefano", "Teacher"], ["alice", "TA"]], :CR=>[["Teacher", "Student"], ["Teacher", "TA"]], :CA=>[["Teacher", [["Admin"], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Student"]], "TA"], ["Teacher", [["TA"], ["Student"]], "Teacher"]], :Goal=>"Student"})
  #   # => {:Roles=>["Teacher", "Student", "TA"], :Users=>["stefano", "alice", "bob"], :UA=>[["stefano", "Teacher"], ["alice", "TA"]], :CR=>[["Teacher", "Student"], ["Teacher", "TA"]], :CA=>[["Teacher", [[], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Student"]], "TA"], ["Teacher", [["TA"], ["Student"]], "Teacher"]], :Goal=>"Student"}
  #
  def forward_slicing(original_policy)
    policy = original_policy.dup
    s = policy[:Roles].select {|r| policy[:UA].map{ |ua| ua[1] }.include?(r)}.to_set
    s_old = Set.new
    while s != s_old
      s_old = s.dup
      policy[:CA].each do |ca|
        check_set = (ca[1].first + [ca.first]).to_set
        if check_set.proper_subset?(s_old)
          s << ca[2]
        end
      end
    end
    unused_roles = policy[:Roles] - s
    policy[:CA] = policy[:CA].select {|ca| !(unused_roles.include?(ca[2]) || (ca[1].first - unused_roles).length < ca[1].first.length)}.to_set
    policy[:CR] = policy[:CR].select {|cr| !(unused_roles.include?(cr[1]))}.to_set
    policy[:CA] = policy[:CA].map do |ca|
      ca[1][1] = ca[1][1] - unused_roles
      ca
    end.to_set
    policy[:UA] = policy[:UA].select {|ua| !(unused_roles.include?(ua[1]))}
    policy[:Roles] -= unused_roles
    policy
  end

  # Public: Compute the backward slicing algorithm within a given policy in order to make the latter smaller and easier to analyze
  #
  # original_policy - The policy object, expressed as an hash  structured in the same way of the return value of +parse_arbac_file(string)+
  #
  # Returns the simplified policy
  #
  # Examples
  #
  #   backward_slicing({:Roles=>["Teacher", "Student", "TA", "Admin"], :Users=>["stefano", "alice", "bob"], :UA=>[["stefano", "Teacher"], ["alice", "TA"]], :CR=>[["Teacher", "Student"], ["Teacher", "TA"]], :CA=>[["Teacher", [["Admin"], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Student"]], "TA"], ["Teacher", [["TA"], ["Student"]], "Teacher"]], :Goal=>"Student"})
  #   # => {:Roles=>["Teacher", "Student", "TA"], :Users=>["stefano", "alice", "bob"], :UA=>[["stefano", "Teacher"], ["alice", "TA"]], :CR=>[["Teacher", "Student"], ["Teacher", "TA"]], :CA=>[["Teacher", [[], ["Teacher", "TA"]], "Student"], ["Teacher", [[], ["Student"]], "TA"], ["Teacher", [["TA"], ["Student"]], "Teacher"]], :Goal=>"Student"}
  #
  def backward_slicing(original_policy)
    policy = original_policy.dup
    s = Set.new [policy[:Goal]]
    s_old = Set.new
    while s != s_old
      s_old = s.dup
      policy[:CA].each do |ca|
        if s_old.include? ca.last
          s += (ca[1][0] + ca[1][1] + [ca.first])
        end
      end
    end
    unused_roles = original_policy[:Roles] - s
    policy[:CA] = policy[:CA].select{ |ca| !(unused_roles.include?(ca[2])) }.to_set
    policy[:CR] = policy[:CR].select{ |cr| !(unused_roles.include?(cr[1])) }.to_set
    policy[:UA] = policy[:UA].select {|ua| !(unused_roles.include?(ua[1]))}
    policy[:Roles] -= unused_roles
    policy
  end

  def compute_reachability(policy)
    all_states = Set.new
    new_states = Set.new [policy[:UA]]
    found = false
    while !found && (new_states - all_states).length > 0
      old_states = new_states - all_states
      all_states += new_states
      new_states = Set.new
      old_states.each do |current_state|
        policy[:Users].each do |user|
          policy[:CA].each do |assignment|
            s = apply_role_assignment(current_state, user, assignment)
            new_states << s
            if s.find{|i| i.last == policy[:Goal]}
              found = true
              break
            end
          end
          policy[:CR].each do |revocation|
            new_states << apply_role_revocation(current_state, user, revocation)
          end
        end
        break unless !found
      end
    end
    found
  end

  # Internal: Given a current state, a target user and an assignment rule, computes the rule application result state
  #
  # state           - The initial state in which the transition should be applied, represented as a set of arrays +[<user>,<role>]+
  # target          - The string representation of the user to whom assign the new role
  # assignment_rule - The assignment rule, espressed as +[<agent_role>,[[<positive_precondition>,...],[<negative_precondition>,...]],<new_role>]+
  #
  # Returns the state, represented in the same way of the +state+ parameter, resulted from the application of the assignment.
  #
  #   NOTE: if the rule cannot be applied because either there are no users in the initial state with the agent role, the target is not present in the initial state or the preconditions on the target are not satisfied, then the method returns the initial state itself
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
  # state           - The initial state in which the transition should be applied, represented as a set of arrays +[<user>,<role>]+
  # target          - The string representation of the user to whom revoke the role
  # assignment_rule - The revocation rule, espressed as +[<agent_role>,<role_to_revoke>]+
  #
  # Returns the state, expressed as the +state+ parameter, resulted from the application of the revocation.
  #
  #   NOTE: if the rule cannot be applied because either there are no users in the initial state with the agent role or the association <target user,role to be revoked> is not present in the initial state, then the method returns the initial state itself
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

def main(arguments)
  include ArbacVerifier

  if arguments.length != 1
    puts "Wrong number of arguments.\nUsage: verifier.rb <arbac_file.arbac>"
  end

  policy = parse_arbac_file(arguments[0])
  puts (compute_reachability(forward_slicing(backward_slicing(policy))) ? 1 : 0);
  exit 0
end

# Start the verifier
main(ARGV)