#! /usr/bin/env ruby
# :markup: TomDoc

def main(arguments) # :nodoc:
  require_relative './classes/arbac_instance.rb'

  if arguments.length < 1
    puts "Wrong number of arguments.\nUsage: verifier.rb <arbac_file.arbac> ..."
  end

  arguments.each do |arg|
    puts "-------------"
    puts "START #{arg}"
    arbac = ArbacInstance.new arg
    begin
      result = arbac.compute_reachability
      puts "END #{arg} with #{result ? 1 : 0}"
    rescue ComputationTimedOutException => _
      puts "#{arg} COMPUTATION TIMED OUT"
    end
  end
  exit 0
end

# Start the verifier
main(ARGV)