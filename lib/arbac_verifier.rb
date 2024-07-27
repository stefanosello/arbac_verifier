# typed: strict
require 'arbac_verifier/classes/reachability_verifier'

module ARBACVerifier
  class << self
    extend T::Sig

    sig { params(logger: T.nilable(Logger)).returns T.nilable(Logger) }
    attr_writer :logger

    sig { returns Logger }
    def logger
      @logger ||= Logger.new($stdout).tap do |log|
        log.progname = self.name
      end
    end
  end
end