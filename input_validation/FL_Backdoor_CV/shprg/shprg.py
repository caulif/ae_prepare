import pdb
import pickle
import os
import random
from decimal import Decimal, getcontext
getcontext().prec = 1024

class SHPRG:
    def __init__(self, n, m, p, q, filename):
        assert p < q, "p < q"
        assert n < m, "n < m"
 
        self.n = n
        self.m = m
        self.p = p
        self.q = q
        self.filename = filename
        if os.path.exists(filename):
            with open(filename, 'rb') as file:
                self.A = pickle.load(file)
        else:
            self.A = [[random.randint(0, q - 1) for _ in range(m)] for _ in range(n)]
            with open(filename, 'wb') as file:
                pickle.dump(self.A, file)

    def G(self, s):
        s = [[s]]
        product = []
        for j in range(self.m):
            sum_result = 0
            for i in range(self.n):
                sum_result += self.A[i][j] * s[i][0]
            product.append(sum_result % self.q)
        product = [Decimal(product[j]) for j in range(self.m)]
        p = Decimal(self.p)
        q = Decimal(self.q)

        result = [int((x * p / q + Decimal('0.5'))) for x in product]

        return result

    def generate(self, seed, length, max_mask):
        s = seed
        extended_vector = self.G(s)
        if length > self.m:
            repeated_vector = (extended_vector * (length // self.m + 1))[:length]
            return [x * max_mask / self.p for x in repeated_vector]
        else:
            ans = extended_vector[:length]
            # return ans
            return [x * max_mask / self.p for x in ans]

    def generate_seeds(self, length):
        seeds = [random.randint(0, self.q - 1) for _ in range(length)]
        return seeds

    def server_sum_hprg(self, seeds, length, max_mask):
        sum_seed = sum(seeds)
        extended_vector = self.generate(sum_seed, length, max_mask)
        return extended_vector

    def client_sum_hprg(self, seeds, length, max_mask):
        sum_vector = [0 for _ in range(length)]
        for seed in seeds:
            temp_vector = self.generate(seed, length, max_mask)
            sum_vector = [(sum_vector[i] + temp_vector[i]) % self.p for i in range(length)]

        return [x for x in sum_vector]


def load_initialization_values(filename):
    with open(filename, 'rb') as file:
        return pickle.load(file)