import pickle
import os
import random
import numpy as np
from decimal import Decimal, getcontext

getcontext().prec = 1024

import pickle
import os
import random
import numpy as np

class HPRF:
    def __init__(self, n, m, p, q, filename):
        assert p < q, "p < q"
        assert n < m, "n < m"

        self.n = n
        self.m = m
        self.p = p
        self.q = q
        self.filename = filename
        self.q_half = q // 2  # Pre-computed constant

        if os.path.exists(filename):
            with open(filename, 'rb') as file:
                A_list_of_lists = pickle.load(file)
                self.A = A_list_of_lists
                self.A_np = np.array(A_list_of_lists, dtype=object)
        else:
            self.A = [[random.randint(0, q - 1) for _ in range(m)] for _ in range(n)]
            self.A_np = np.array(self.A, dtype=object)
            with open(filename, 'wb') as file:
                pickle.dump(self.A, file)

        
        # Pre-compute column sums
        self.A_col_sums_np = np.sum(self.A_np, axis=0, dtype=object)

    def G_batch(self, s_scalars_batch_np):
        """Optimized batch computation"""
        # Use broadcasting to compute all (s * col_sum) % q
        products = (s_scalars_batch_np[:, None] * self.A_col_sums_np) % self.q
        
        # Vectorized integer operations for rounding
        result_matrix = (products * self.p + self.q_half) // self.q
        return result_matrix.astype(object)

    def G(self, s):
        s_np = np.array([s], dtype=np.int64)
        result_matrix = self.G_batch(s_np)
        return result_matrix[0].tolist()

    def hprf(self, k, x, length):
        if length == 0:
            return []

        num_s_values_to_generate = (length + self.m - 1) // self.m
        counters = np.arange(num_s_values_to_generate, dtype=object)
        py_k, py_x, py_q = int(k), int(x), int(self.q)
        s_scalars_list = [(py_k * (py_x + c_val)) % py_q for c_val in counters]
        s_scalars_np = np.array(s_scalars_list, dtype=object)

        g_results_matrix = self.G_batch(s_scalars_np)
        all_output_values_np = g_results_matrix.flatten(order='C')
        return all_output_values_np[:length].tolist()


    def hprg(self, seed, length):
        """
         Generates a pseudo-random sequence of a specified length.

         Args:
             seed (int): The seed value.
             length (int): The length of the sequence.

         Returns:
             list: The pseudo-random sequence.
         """
        s = seed
        extended_vector = self.G(s)
        if length > self.m:
            repeated_vector = (extended_vector * (length // self.m + 1))[:length]
            return repeated_vector
        else:
            return extended_vector[:length]


def load_initialization_values(filename):
    """
    Loads initialization values from a file.

    Args:
        filename (str): The filename.

    Returns:
        tuple: Initialization values (n, m, p, q).
    """
    with open(filename, 'rb') as file:
        return pickle.load(file)
    
