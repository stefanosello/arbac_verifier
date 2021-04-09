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

end