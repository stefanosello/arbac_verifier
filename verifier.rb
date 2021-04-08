#! /usr/bin/env ruby
# :markup: TomDoc

module ArbacVerifier
  require 'set'

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
    lines = file.readlines.map{|l| l.chomp!(" ;\n")}
    result = Hash.new
    lines.each do |line|
      row = line.split(" ")
      key = row[0].to_sym
      result[key] = Set.new row.slice(1,row.length)
      if key === :Goal
        result[key] = result[key].first
      elsif [:UA, :CR, :CA].include? key
        result[key] = result[key].map{|item| item.slice(1,item.length - 2).split(",")}
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
  # original_policy - The policy object, expressed as an hash
  #                   :Roles - set of strings, the available roles in the policy
  #                   :Users - set of strings, the users present in the policy
  #                   :UA    - set of arrays of (2) strings, the first string of each inner array represents the user, the second the role that the user has
  #                   :UR    - set of arrays of (2) strings, the first string of each inner array represents the role in power of revoke, the second the role to be revoked
  #                   :CA    - set of arrays of (3) mixed where the first element is a string representing the role in power of assign; the second element is an array of two sets of strings,
  #                            representing respectively the positive preconditions and the negative ones needed to apply the assignment; the third element is a string representing the role to be assigned
  #                   :Goal  - string, representing the role object of the reachability analysis for the given policy
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
    policy[:CA] = policy[:CA].select {|ca| !(unused_roles.include?(ca[2]) || (ca[1].first - unused_roles).length < ca[1].first.length)}
    policy[:CR] = policy[:CR].select {|cr| !(unused_roles.include?(cr[1]))}
    policy[:CA] = policy[:CA].map do |ca|
      ca[1][1] = ca[1][1] - unused_roles
      ca
    end
    policy[:Roles] -= unused_roles
    policy
  end

  # Public: Compute the backward slicing algorithm within a given policy in order to make the latter smaller and easier to analyze
  #
  # original_policy - The policy object, expressed as an hash
  #                   :Roles - set of strings, the available roles in the policy
  #                   :Users - set of strings, the users present in the policy
  #                   :UA    - set of arrays of (2) strings, the first string of each inner array represents the user, the second the role that the user has
  #                   :UR    - set of arrays of (2) strings, the first string of each inner array represents the role in power of revoke, the second the role to be revoked
  #                   :CA    - set of arrays of (3) mixed where the first element is a string representing the role in power of assign; the second element is an array of two sets of strings,
  #                            representing respectively the positive preconditions and the negative ones needed to apply the assignment; the third element is a string representing the role to be assigned
  #                   :Goal  - string, representing the role object of the reachability analysis for the given policy
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
        if s_old.include? ca[2]
          s += ca[1][0] + ca[1][1] + [ca.first]
        end
      end
    end
    unused_roles = original_policy[:Roles] - s
    policy[:CA] = policy[:CA].select{ |ca| !(unused_roles.include?(ca[2])) }
    policy[:CR] = policy[:CR].select{ |cr| !(unused_roles.include?(cr[1])) }
    policy[:Roles] -= unused_roles
    policy
  end

end

def main(arguments)
  include ArbacVerifier

  puts arguments.length
  if arguments.length != 1
    puts "Wrong number of arguments.\nUsage: verifier.rb <arbac_file.arbac>"
  end

  policy = parse_arbac_file(arguments[0])
  puts policy
  puts "FORWARD SLICING ---------------"
  puts forward_slicing(policy)
  puts "BACKWARD SLICING --------------"
  puts backward_slicing(policy)
  exit 0
end

# Start the verifier
main(ARGV)