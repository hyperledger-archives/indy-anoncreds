# AnonCreds: Anonymous credentials protocol implementation in python

Implementation of Anonymous Credential using python.

## Setup the project and dependencies
Execute `bash setup.sh`

## Questions related to AnonCreds and their responses from Dmitry

1. What does *Gamma* denote? 
A: It is a number derived as 1 + product of ‘b’ and ‘rho’. It must be prime, so a few (b,rho) must be generated to have this.

2. Is *r* random prime or just a random number `< rho`?
A: Just random number

3. What does the combination (Gamma, rho, g, h) denote?
A: It is a 4-tuple of numbers that constitutes a public parameter to compute pseudonyms.

# Questions regarding Predicate implementation with AnonCreds:
4. In Prepare Proof, step 2, is (mj >= zj) the condition we want to prove? 
A: Yes

5. Are u1, u2 ... u4 random integers? If yes, is there any specific criteria to calculate them or just brute-force mechanism?
A: any integers that satisfy equation. They must be found by some algorithm, possibly bruteforce for small Delta

6. Is the count of `u` fixed a 4 or will it vary with number of attributes? What exactly is u?
A: always 4

7. Is the mathematical proof of the implementation still valid, with all the changes needed to support predicates?
A: Everything remains valid, yes
