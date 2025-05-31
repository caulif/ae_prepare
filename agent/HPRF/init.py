import pickle

import sympy

prime_bits = 64
prime = sympy.randprime(2 ** (prime_bits - 1), 2 ** prime_bits) 
p = prime
q = prime * 5
print(p, q)
initialization_values = (128, 512, p, q)

# initialization_values = (128, 512, 95325756275086363396928995575400109969095977033837034603059483527243639993519, 476628781375431816984644977877000549845479885169185173015297417636218199967595)

with open(r"agent\\HPRF\\initialization_values", 'wb') as file:
    pickle.dump(initialization_values, file)
