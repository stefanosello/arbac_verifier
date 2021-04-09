#! /usr/bin/env ruby
# :markup: TomDoc

def main(arguments) # :nodoc:
  require_relative './classes/arbac_instance.rb'

  if arguments.length != 1
    puts "Wrong number of arguments.\nUsage: verifier.rb <arbac_file.arbac>"
  end

  arbac = ArbacInstance.new arguments[0]
  puts arbac.compute_reachability
  exit 0
end

# Start the verifier
main(ARGV)