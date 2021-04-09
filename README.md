# arbac_verifier
[![Documentation Status](https://readthedocs.org/projects/ansicolortags/badge/?version=latest)](https://mr5he11.github.io/arbac_verifier) [![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Naereen/badges/)


Program written in ruby to verify some simple istances of the arbac role reachability problem.
You can find documentation [here](https://mr5he11.github.io/arbac_verifier).

### Example
The execution of `src/main.rb` within all provided policies, within a Macbook pro 16 2020 (i9, 16GB of RAM), leads to the following result:
```{bash}
❯ ./src/main.rb ./policies/policy1.arbac ./policies/policy2.arbac ./policies/policy3.arbac ./policies/policy4.arbac ./policies/policy5.arbac ./policies/policy6.arbac ./policies/policy7.arbac ./policies/policy8.arbac
-------------
START ./policies/policy1.arbac
Time: 4.7e-05, Number of States: 1
Time: 0.002327, Number of States: 21
Time: 0.046811, Number of States: 206
END ./policies/policy1.arbac with 1
-------------
START ./policies/policy2.arbac
Time: 5.1e-05, Number of States: 1
Time: 0.001839, Number of States: 16
Time: 0.023987, Number of States: 116
Time: 0.199687, Number of States: 506
Time: 0.910298, Number of States: 1488
Time: 3.016245, Number of States: 3132
Time: 8.186207, Number of States: 4881
Time: 18.307823, Number of States: 5724
Time: 30.83677, Number of States: 5052
Time: 43.201684, Number of States: 3296
Time: 50.926555, Number of States: 1520
Time: 54.83462, Number of States: 448
Time: 56.447622, Number of States: 64
END ./policies/policy2.arbac with 0
-------------
START ./policies/policy3.arbac
Time: 2.9e-05, Number of States: 1
Time: 0.001416, Number of States: 14
END ./policies/policy3.arbac with 1
-------------
START ./policies/policy4.arbac
Time: 2.8e-05, Number of States: 1
Time: 0.001865, Number of States: 21
Time: 0.033973, Number of States: 206
Time: 0.390699, Number of States: 1250
Time: 2.558402, Number of States: 5235
Time: 13.642994, Number of States: 15979
Time: 54.29324, Number of States: 36570
Time: 140.033086, Number of States: 63534
Time: 311.643867, Number of States: 83781
Time: 572.588074, Number of States: 82809
Time: 861.331869, Number of States: 59616
Time: 1086.624904, Number of States: 29592
Time: 1193.012846, Number of States: 9072
Time: 1236.541877, Number of States: 1296
END ./policies/policy4.arbac with 0
-------------
START ./policies/policy5.arbac
Time: 2.9e-05, Number of States: 1
Time: 0.002582, Number of States: 21
Time: 0.039117, Number of States: 206
Time: 0.579331, Number of States: 1250
Time: 3.804942, Number of States: 5235
Time: 18.062846, Number of States: 15979
Time: 57.869794, Number of States: 36570
Time: 160.095505, Number of States: 63534
Time: 345.35307, Number of States: 83781
Time: 638.854461, Number of States: 82809
Time: 954.318604, Number of States: 59616
Time: 1191.837213, Number of States: 29592
Time: 1304.281398, Number of States: 9072
Time: 1347.443246, Number of States: 1296
END ./policies/policy5.arbac with 0
-------------
START ./policies/policy6.arbac
Time: 7.2e-05, Number of States: 1
Time: 0.002591, Number of States: 21
END ./policies/policy6.arbac with 1
-------------
START ./policies/policy7.arbac
Time: 2.9e-05, Number of States: 1
Time: 0.001553, Number of States: 14
Time: 0.018831, Number of States: 85
Time: 0.130516, Number of States: 292
Time: 0.736709, Number of States: 620
Time: 2.026497, Number of States: 832
Time: 3.78869, Number of States: 688
Time: 5.181362, Number of States: 320
Time: 5.775139, Number of States: 64
END ./policies/policy7.arbac with 0
-------------
START ./policies/policy8.arbac
Time: 3.3e-05, Number of States: 1
Time: 0.00196, Number of States: 21
Time: 0.040365, Number of States: 206
Time: 0.613404, Number of States: 1250
Time: 4.06097, Number of States: 5235
Time: 18.342251, Number of States: 15979
Time: 61.33347, Number of States: 36570
Time: 164.839486, Number of States: 63534
Time: 356.289757, Number of States: 83781
Time: 648.922124, Number of States: 82809
Time: 967.984204, Number of States: 59616
Time: 1197.612737, Number of States: 29592
Time: 1303.787445, Number of States: 9072
Time: 1342.892501, Number of States: 1296
END ./policies/policy8.arbac with 0
```
