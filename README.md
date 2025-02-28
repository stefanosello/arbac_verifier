![logo.png](logo.png)

[![codecov](https://codecov.io/github/stefanosello/arbac_verifier/branch/main/graph/badge.svg?token=VXWHKJUJR2)](https://codecov.io/github/stefanosello/arbac_verifier)
[![Ruby Gem](https://github.com/stefanosello/arbac_verifier/actions/workflows/gem-push.yml/badge.svg?branch=main)](https://github.com/stefanosello/arbac_verifier/actions/workflows/gem-push.yml)
[![Gem Version](https://badge.fury.io/rb/arbac_verifier.svg)](https://badge.fury.io/rb/arbac_verifier)
[![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Naereen/badges/)


**ARBAC Verifier** is a Ruby gem designed to facilitate the modeling and verification of Administrative Role-Based Access Control (ARBAC) policies. With this tool, you can efficiently model ARBAC policies and perform verification tasks to determine if a specific role (`Goal`) can be achieved starting from a given set of states (user-to-role assignments).

This gem is grounded in comprehensive theoretical foundations, which you can explore in detail through the [official security course slides](https://secgroup.dais.unive.it/wp-content/uploads/2020/04/arbac.pdf) provided by [Ca' Foscari University](https://www.unive.it/pag/13526) of Venice. 

## Installation
The `arbac_verifier` gem can be installed from [rubygems.org](https://rubygems.org/gems/arbac_verifier) from command line: 
```{bash}
gem install arbac_verifier
```
or by adding the following line to your `Gemfile` project:
```{ruby}
gem 'arbac_verifier', '~> 1.1', '>= 1.1.0'
```

## ARBAC definition file
An ARBAC (Attribute-Based Role-Based Access Control) policy definition comprises four key components:
- **Users**: A set of individuals who are part of the system under analysis.
- **Roles**: A set of roles that can be assigned to or removed from users.
- **Can-Assign Rules**: These rules specify which roles can be assigned to users. Each rule includes:
  - The role that has the authority to make the assignment.
  - The role to be assigned.
  - Positive preconditions: Specific roles that the user must already possess to be eligible for the new role.
  - Negative preconditions: Specific roles that the user must not possess to be eligible for the new role.
- **Can-Revoke Rules**: These rules specify which roles can be revoked from users. Each rule includes:
  - The role that has the authority to revoke.
  - The role to be revoked. 

This structure ensures that role assignments and revocations are controlled and based on the current state of the user's roles.
In order to represent a policy based on this definition, we can use `arbac` files, which should follow this format:
```
Roles Teacher Student TA ;
Users stefano alice bob ;
UA <stefano,Teacher> <alice,TA> ;
CR <Teacher,Student> <Teacher,TA> ;
CA <Teacher,-Teacher&-TA,Student> <Teacher,-Student,TA> <Teacher,TA&-Student,Teacher> ;
Goal Student ;
``` 
- Each line starts with an *header* that explains which information will be represented
  - `Roles` and `Users` are straight forward
  - `UA` are initial User Assignments, i.e. user-role assignments, where each item is a pair of `<user,role>`
  - `CR` are Can-Revoke rules, where each item is a pair of `<revoker role, revokable role>`
  - `CA` are Can-Assign rules, where each item is a tern of `<assigner role, <positive1&positive2&-negative1&-negative2>, assignable role>`
  - `Goal` is not an ARBAC property: it is the target role for which the reachability should be verified
- Each line ends with a `;`
- Items of each line are space-separated

## Usage
Once installed, the gem can be used to manage different tasks related to arbac policies.
### Create ARBAC instance
ARBAC instances can be created by providing the path of an `.arbac` definition file or passing explicit instance attributes.
```ruby
require 'arbac_verifier'
require 'set

# Create new Arbac instance from .arbac file
policy0 = ARBACVerifier::Instance.new(path: 'policy0.arbac')

# Create new Arbac instance passing single attributes
policy1 = ARBACVerifier::Instance.new(
  goal: :Student,
  roles: [:Teacher, :Student, :TA].to_set,
  users: ["stefano", "alice", "bob"].to_set,
  user_to_role: [ARBACVerifier::UserRole.new("stefano", :Teacher), ARBACVerifier::UserRole.new("alice", :TA)].to_set,
  can_assign_rules: [
                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [].to_set, [:Teacher, :TA].to_set, :Student),
                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [].to_set, [:Student].to_set, :TA),
                      ARBACVerifier::Rules::CanAssign.new(:Teacher, [:TA].to_set, [:Student].to_set, :Teacher)
                    ].to_set,
  can_revoke_rules: [
                      ARBACVerifier::Rules::CanRevoke.new(:Teacher, :Student),
                      ARBACVerifier::Rules::CanRevoke.new(:Teacher, :TA)
                    ].to_set
)
```
### Instance pruning
Once the problem instance has been defined, the gem provides two simplification algorithms that can be used to reduce the size of the reachability problem.
These algorithms do not modify the original policy and return a new simplified policy.
```ruby
require 'arbac_verifier'

include ARBACVerifier::Utils

# apply backward slicing
policy0bs =  backward_slicing(policy0)

# apply forward slicing
policy0fs = forward_slicing(policy0)
```
### Role reachability solution
A Role Reachability Problem solution can be computed using the `ArbacReachabilityVerifier` class.
```ruby
require 'arbac_verifier'

# Creare new reachability verifier instance starting from an .arbac file
verifier0 = ARBACVerifier::ReachabilityVerifier.new(path: 'policy0.arbac')

# or from an already created ArbacInstance
verifier1 = ARBACVerifier::ReachabilityVerifier.new(instance: policy1)

# and then compute reachability
verifier0.verify # => true
```
**NB:** when a verifier instance is created starting from an `.arbac` file, backward and forward slicing are applied to the parsed policy.
### Logging
By default, `ARBACVerifier::ReachabilityVerifier` logs context info to `$stdout`. Custom loggers can be set using `ARBACVerifier::ReachabilityVerifier#set_logger(logger)`.
