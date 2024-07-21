![logo.png](logo.png)

[![Documentation Status](https://readthedocs.org/projects/ansicolortags/badge/?version=latest)](https://mr5he11.github.io/arbac_verifier) [![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Naereen/badges/)


Program written in ruby to verify some simple istances of the arbac role reachability problem.
You can find documentation [here](https://mr5he11.github.io/arbac_verifier).

### Example
The execution of `src/main.rb` within all provided policies leads to the following result:
```{bash}
❯ ./src/main.rb ./docs/policies/policy1.arbac ./docs/policies/policy2.arbac ./docs/policies/policy3.arbac ./docs/policies/policy4.arbac ./docs/policies/policy5.arbac ./docs/policies/policy6.arbac ./docs/policies/policy7.arbac ./docs/policies/policy8.arbac
-------------
START ./docs/policies/policy1.arbac
END ./docs/policies/policy1.arbac with 1
-------------
START ./docs/policies/policy2.arbac
END ./docs/policies/policy2.arbac with 0
-------------
START ./docs/policies/policy3.arbac
END ./docs/policies/policy3.arbac with 1
-------------
START ./docs/policies/policy4.arbac
END ./docs/policies/policy4.arbac with 0
-------------
START ./docs/policies/policy5.arbac
END ./docs/policies/policy5.arbac with 0
-------------
START ./docs/policies/policy6.arbac
END ./docs/policies/policy6.arbac with 1
-------------
START ./docs/policies/policy7.arbac
END ./docs/policies/policy7.arbac with 0
-------------
START ./docs/policies/policy8.arbac
END ./docs/policies/policy8.arbac with 0
```
