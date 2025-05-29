import pickle
import os
import random
import numpy as np
from decimal import Decimal, getcontext

getcontext().prec = 1024

class SHPRG:
    def __init__(self, n, m, p, q, filename):
        """
        Initializes the SHPRF object.

        Args:
            n (int): Number of rows in the matrix.
            m (int): Number of columns in the matrix.
            p (int): The first parameter for the modulo operation.
            q (int): The second parameter for the modulo operation.
            filename (str): The filename to store the matrix.
        """
        assert p < q, "p < q"  # Ensure p is less than q
        assert n < m, "n < m"  # Ensure n is less than m

        self.n = n
        self.m = m
        self.p = p
        self.q = q
        self.filename = filename
        self.p_float = float(p)
        self.q_float = float(q)
        self.p_div_q_float = self.p_float / self.q_float

        # Load the matrix if the file exists
        if os.path.exists(filename):
            with open(filename, 'rb') as file:
                A_list_of_lists = pickle.load(file)
                self.A = A_list_of_lists
                self.A_np = np.array(A_list_of_lists, dtype=np.int64)
        # Otherwise, generate a new random matrix and save it to the file
        else:
            self.A = [[random.randint(0, q - 1) for _ in range(m)] for _ in range(n)]
            self.A_np = np.array(self.A, dtype=np.int64)
            with open(filename, 'wb') as file:
                pickle.dump(self.A, file)
        
        # Pre-calculate sum of columns of A
        self.A_col_sums_np = np.sum(self.A_np, axis=0, dtype=np.int64)

    def G_batch(self, s_scalars_batch_np):
        """
        Batch version of G function using NumPy for better performance.
        
        Args:
            s_scalars_batch_np: 1D NumPy array of s_scalar values.
            
        Returns:
            2D NumPy array of shape (num_s_values, m).
        """
        product_matrix = (s_scalars_batch_np[:, np.newaxis] * self.A_col_sums_np) % self.q
        scaled_product_matrix = product_matrix.astype(float) * self.p_div_q_float + 0.5
        result_matrix = np.floor(scaled_product_matrix).astype(int)
        return result_matrix

    def G(self, s):
        """
        Calculates the matrix product A^T * s and maps the result to the range [0, p).
        Now uses the batch version internally for better performance.

        Args:
            s (int): The seed value.

        Returns:
            list: The mapped result vector.
        """
        s_np = np.array([s], dtype=np.int64)
        result_matrix = self.G_batch(s_np)
        return result_matrix[0].tolist()

    def hprf(self, k, x, length):
        """
        Generates a pseudo-random sequence using batch processing for better performance.
        
        Args:
            k (int): The key value.
            x (int): The input value.
            length (int): The desired length of the output sequence.
            
        Returns:
            list: The generated pseudo-random sequence.
        """
        if length == 0:
            return []

        num_s_values_to_generate = (length + self.m - 1) // self.m
        
        # Generate s_values
        counters = np.arange(num_s_values_to_generate, dtype=np.int64)
        py_k, py_x, py_q = int(k), int(x), int(self.q)
        s_scalars_list = [(py_k * (py_x + c_val)) % py_q for c_val in counters]
        s_scalars_np = np.array(s_scalars_list, dtype=np.int64)

        # Process all s_values in a batch
        g_results_matrix = self.G_batch(s_scalars_np)
        
        # Flatten the matrix and take the required length
        all_output_values_np = g_results_matrix.flatten(order='C')
        
        return all_output_values_np[:length].tolist()

    def list_hprf(self, k, x, length):
        result = []
        counter = 0
        offset = k[0][0]
        initial_value = k[0][1]

        while len(result) < length:
            s = (initial_value * (x + counter)) % self.q
            generated_values = self.G(s)
            for val in generated_values:
                result.append((offset, val))

            counter += 1
        return result[:length]


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


    def list_hprg(self, seed, length):
        """
        Generates a pseudo-random sequence of a specified length.
0
        Args:
            seed (int): The seed value.
            length (int): The length of the sequence.

        Returns:
            list: The pseudo-random sequence.
        """
        result = []
        offset = seed[0][0]
        initial_value = seed[0][1]
        extended_vector = self.G(initial_value)
        if length > self.m:
            repeated_vector = (extended_vector * (length // self.m + 1))[:length]
            for i in range(len(repeated_vector)):
                result.append((offset, repeated_vector[i]))
            return result
        else:
            for i in range(len(extended_vector)):
                result.append((offset, extended_vector[i]))
            return result[:length]


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
    

if __name__ == "__main__":
    initialization_values_filename = r"agent\\HPRF\\initialization_values"
    n, m, p, q = load_initialization_values(initialization_values_filename)
    filename = r"matrix"
    shprg = SHPRG(n, m, p, q, filename)
    
    # 测试参数
    vector_len = 100  # 向量长度
    value = 10       # 每个向量的值
    num_vectors = 204  # 向量数量
    
    print("【测试1：先hprf再相加】")
    # 对每个值进行hprf
    hprf_results = []
    for i in range(num_vectors):
        result = shprg.hprf(10, 1, vector_len)
        print(result[0])
        hprf_results.append(result)
    
    # 将结果相加
    sum_after_hprf = [0] * vector_len
    for result in hprf_results:
        for i in range(vector_len):
            sum_after_hprf[i] = (sum_after_hprf[i] + result[i]) % p

    
    print(f"先hprf再相加的结果（前5个值）: {sum_after_hprf[:5]}")
    
    print("\n【测试2：先相加再hprf】")
    # 先计算总和
    total_sum = (value * num_vectors) % q
    # 对总和进行hprf
    hprf_after_sum = shprg.hprf(total_sum, 1, vector_len)
    
    print(f"先相加再hprf的结果（前5个值）: {hprf_after_sum[:5]}")
    
    # # 比较两种方式的结果
    # print("\n【结果比较】")
    # print(f"两种方式结果是否相同: {sum_after_hprf == hprf_after_sum}")
    # if sum_after_hprf != hprf_after_sum:
    #     print("不同位置的值：")
    #     for i in range(vector_len):
    #         if sum_after_hprf[i] != hprf_after_sum[i]:
    #             print(f"位置 {i}: 方式1={sum_after_hprf[i]}, 方式2={hprf_after_sum[i]}")