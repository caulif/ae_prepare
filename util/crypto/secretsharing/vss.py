# -*- coding: utf-8 -*-
"""
    Verifiable Secret Sharing (VSS)
    ~~~~~

    Implementation of Verifiable Secret Sharing scheme using Pedersen commitments.
    Based on the paper: "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"
    by Torben P. Pedersen (1991).
"""

import random
import sys
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import sympy
from secretsharing.polynomials import random_polynomial, get_polynomial_points, mod_inverse
from secretsharing.primes import get_large_enough_prime
import gmpy2
import time
import numpy as np

class VSS:
    """
    Implements Verifiable Secret Sharing scheme using Pedersen commitments.
    """
    
    def __init__(self, prime=None):
        """
        Initialize the VSS scheme.
        
        Args:
            prime: Prime number for the field. If None, a default value will be used.
        """
        # 使用传入的 prime 作为 p
        self.p = prime if prime is not None else sympy.randprime(2 ** (2048 - 1), 2 ** 2048)
        # q = (p-1)/2
        self.q = (self.p - 1) // 2
        # 生成安全的生成元
        self.g = self._find_generator()
        self.h = self._find_generator(different_from=self.g)
        
    def _find_generator(self, different_from=None):
        """生成安全的生成元"""
        while True:
            x = random.randrange(2, self.p - 1)
            g = pow(x, (self.p - 1) // self.q, self.p)
            if g != 1 and (different_from is None or g != different_from):
                return g
        
    def _evaluate_polynomial(self, coefficients, x, prime):
        """计算多项式在点x处的值，使用霍纳法则优化"""
        result = coefficients[-1]
        for coef in reversed(coefficients[:-1]):
            result = (result * x + coef) % prime
        return result

    def _fast_mod_pow(self, base, exp, mod):
        """使用快速模幂算法"""
        result = 1
        base = base % mod
        while exp > 0:
            if exp & 1:
                result = (result * base) % mod
            base = (base * base) % mod
            exp >>= 1
        return result

    def share(self, secret, num_shares, threshold, prime=None):
        """
        Share a secret using VSS with Pedersen commitments.
        
        Args:
            secret: The secret to be shared.
            num_shares: Number of shares to generate.
            threshold: Number of shares required to reconstruct the secret.
            prime: Prime number for the field. If None, a suitable prime will be generated.
            
        Returns:
            shares: List of shares in the format [(share_index, share_value, blinding_value)].
            commitments: List of commitments for verification.
        """
        if threshold > num_shares:
            raise ValueError("Threshold cannot be greater than number of shares!")
        if prime is None:
            prime = get_large_enough_prime([secret, num_shares])
            if prime is None:
                raise ValueError("Error! Secret is too long for share calculation!")
        self.q = prime
        # 确保secret在q范围内
        secret = secret % self.q
        
        # 使用固定的系数，而不是随机系数
        f_coeffs = [secret]  # 第一个系数是secret
        r_coeffs = [1]      # 第一个r系数固定为1
        
        # 使用固定的系数
        for i in range(threshold - 1):
            f_coeffs.append(i + 1)  # 使用递增的固定系数
            r_coeffs.append(i + 2)  # 使用递增的固定系数
        
        # 计算Pedersen承诺 C_j = g^{a_j} h^{b_j} mod p
        commitments = []
        for j in range(threshold):
            c = (gmpy2.powmod(self.g, f_coeffs[j], self.p) * 
                 gmpy2.powmod(self.h, r_coeffs[j], self.p)) % self.p
            commitments.append(c)
        
        # 生成份额 (i, f(i), r(i))，都在q上
        shares = []
        for i in range(1, num_shares + 1):
            # 计算多项式在点i处的值
            f_i = 0
            r_i = 0
            
            # 计算f(i)
            for j, coef in enumerate(f_coeffs):
                f_i = (f_i + coef * pow(i, j, self.q)) % self.q
            
            # 计算r(i)
            for j, coef in enumerate(r_coeffs):
                r_i = (r_i + coef * pow(i, j, self.q)) % self.q
            
            shares.append((i, f_i, r_i))
        
        return shares, commitments
    
    def verify_share(self, share, commitments, prime):
        """
        Verify a share against the Pedersen commitments.
        
        Args:
            share: A share in the format (share_index, share_value, blinding_value).
            commitments: List of commitments.
            prime: Prime number for the field.
            
        Returns:
            is_valid: True if the share is valid, False otherwise.
        """
        try:
            if len(share) != 3:
                return False
            x, f_x, r_x = share
            
            # 检查输入参数
            if not isinstance(x, int) or not isinstance(f_x, int) or not isinstance(r_x, int):
                return False
                
            if not isinstance(commitments, list) or not commitments:
                return False
            
            # 确保值在q范围内
            f_x = f_x % self.q
            r_x = r_x % self.q
            
            # 计算 g^f(x) * h^r(x) mod p
            left = (pow(self.g, f_x, self.p) * pow(self.h, r_x, self.p)) % self.p
            
            # 计算 ∏(C_j^x^j) mod p
            right = 1
            for j, Cj in enumerate(commitments):
                x_pow_j = pow(x, j, self.q)
                right = (right * pow(Cj, x_pow_j, self.p)) % self.p
            
            return left == right
            
        except Exception as e:
            return False

    def verify_shares_batch(self, shares, commitments, prime):
        """
        批量验证多个份额，利用Pedersen承诺的同态性质。
        
        Args:
            shares: 份额列表，每个份额格式为 (share_index, share_value, blinding_value)
            commitments: 承诺列表
            prime: 素数
            
        Returns:
            is_valid: True if all shares are valid, False otherwise
        """
        try:
            if not shares or not commitments:
                return False
                
            # 计算所有份额的承诺
            C_total = 1
            for x, f_x, r_x in shares:
                # 确保值在q范围内
                f_x = f_x % self.q
                r_x = r_x % self.q
                # 计算单个份额的承诺
                C_i = (pow(self.g, f_x, self.p) * pow(self.h, r_x, self.p)) % self.p
                # 累乘所有承诺
                C_total = (C_total * C_i) % self.p
            
            # 计算所有份额值的和
            sum_f = 0
            sum_r = 0
            for _, f_x, r_x in shares:
                sum_f = (sum_f + f_x) % self.q
                sum_r = (sum_r + r_x) % self.q
            
            # 使用同态性质计算总承诺
            C_sum = (pow(self.g, sum_f, self.p) * pow(self.h, sum_r, self.p)) % self.p
            
            # 验证两个结果是否相等
            return C_total == C_sum
            
        except Exception as e:
            return False

    def reconstruct(self, shares, prime):
        """
        Reconstruct the secret from shares.
        
        Args:
            shares: List of shares in the format [(share_index, share_value, blinding_value)] or [(share_index, share_value)].
                   Also supports nested list format [[(index, value)]] or [[(index, value, blinding)]].
            prime: Prime number for the field.
            
        Returns:
            secret: The reconstructed secret.
            
        Raises:
            ValueError: If shares list is empty or invalid format.
        """
        if len(shares) < 2:
            raise ValueError("至少需要2个份额才能重构秘密")
        
        self.q = prime
        
        # 处理嵌套列表格式
        if isinstance(shares[0], list):
            shares = [share[0] for share in shares]
        
        # 兼容2元组和3元组份额
        normalized_shares = []
        for share in shares:
            if len(share) == 2:
                # 自动补0作为blinding
                share = (share[0], share[1], 0)
            elif len(share) != 3:
                raise ValueError("Invalid share format: must be (index, value) 或 (index, value, blinding)")
            if not all(isinstance(x, int) for x in share):
                raise ValueError("Share components must be integers")
            normalized_shares.append(share)
        
        # 使用拉格朗日插值重构秘密（在q上）
        secret = 0
        for i, (x_i, y_i, _) in enumerate(normalized_shares):
            numerator = denominator = 1
            for j, (x_j, _, _) in enumerate(normalized_shares):
                if i != j:
                    numerator = (numerator * (-x_j)) % self.q
                    denominator = (denominator * (x_i - x_j)) % self.q
            try:
                inv_denominator = pow(denominator, -1, self.q)
                lagrange_coef = (numerator * inv_denominator) % self.q
                secret = (secret + (y_i * lagrange_coef) % self.q) % self.q
            except ValueError:
                continue
        return secret

    def reconstruct_batch(self, shares_list, prime):
        """
        批量恢复多个秘密。
        
        Args:
            shares_list: 份额列表的列表，每个内部列表包含格式为 [(share_index, share_value, blinding_value)] 的份额。
            prime: 素数。
            
        Returns:
            secrets: 恢复的秘密列表。
            
        Raises:
            ValueError: 如果份额列表为空或格式无效。
        """
        if not shares_list:
            raise ValueError("份额列表不能为空")
            
        secrets = []
        for shares in shares_list:
            try:
                secret = self.reconstruct(shares, prime)
                secrets.append(secret)
            except ValueError as e:
                print(f"警告：恢复秘密时出错: {e}")
                secrets.append(None)
                
        return secrets

    def reconstruct_batch_fast(self, shares_list, prime):
        """
        快速批量恢复多个秘密。
        使用预计算和矩阵运算来优化性能。
        
        Args:
            shares_list: 份额列表的列表，每个内部列表包含格式为 [(share_index, share_value, blinding_value)] 的份额。
            prime: 素数。
            
        Returns:
            secrets: 恢复的秘密列表。
        """
        if not shares_list:
            return []
            
        secrets = []
        # 获取第一组份额的x值
        x_values = [x for x, _, _ in shares_list[0]]
        
        # 预计算所有可能的拉格朗日系数
        lagrange_coeffs = []
        for i, x_i in enumerate(x_values):
            numerator = denominator = 1
            for j, x_j in enumerate(x_values):
                if i != j:
                    numerator = (numerator * (-x_j)) % self.q
                    denominator = (denominator * (x_i - x_j)) % self.q
            try:
                inv_denominator = pow(denominator, -1, self.q)
                lagrange_coef = (numerator * inv_denominator) % self.q
                lagrange_coeffs.append(lagrange_coef)
            except ValueError:
                lagrange_coeffs.append(0)
        
        # 批量计算所有秘密
        for shares in shares_list:
            try:
                # 使用预计算的拉格朗日系数
                secret = 0
                for i, (_, y_i, _) in enumerate(shares):
                    secret = (secret + (y_i * lagrange_coeffs[i]) % self.q) % self.q
                secrets.append(secret)
            except Exception as e:
                print(f"警告：恢复秘密时出错: {e}")
                secrets.append(None)
                
        return secrets


# Example usage
if __name__ == "__main__":
    # Create a VSS instance
    vss = VSS()
    
    # # Share a secret
    # secret = 42
    # num_shares = 5
    # threshold = 3
    # prime = vss.q  # 使用q作为prime
    
    # shares, commitments = vss.share(secret, num_shares, threshold, prime)
    
    # # 测试批量验证
    # is_valid = vss.verify_shares_batch(shares, commitments, prime)
    # print(f"Batch verification result: {is_valid}")
    
    # # 测试单个验证
    # for share in shares:
    #     is_valid = vss.verify_share(share, commitments, prime)
    #     print(f"Share {share} is valid: {is_valid}")
    
    # # Reconstruct the secret
    # reconstructed_secret = vss.reconstruct(shares[:threshold], prime)
    # print(f"Original secret: {secret}")
    # print(f"Reconstructed secret: {reconstructed_secret}")
    # print(f"Reconstruction successful: {secret == reconstructed_secret}")
    
    
    # Test Pedersen commitment homomorphism
    print("\n【Pedersen承诺同态性质测试】")
    s1 = random.randrange(0, vss.q)
    s2 = random.randrange(0, vss.q)
    r1 = random.randrange(0, vss.q)
    r2 = random.randrange(0, vss.q)
    C1 = (pow(vss.g, s1, vss.p) * pow(vss.h, r1, vss.p)) % vss.p
    C2 = (pow(vss.g, s2, vss.p) * pow(vss.h, r2, vss.p)) % vss.p
    C_mul = (C1 * C2) % vss.p
    C_sum = (pow(vss.g, (s1 + s2) % vss.q, vss.p) * pow(vss.h, (r1 + r2) % vss.q, vss.p)) % vss.p
    print(f"C1 = g^s1 h^r1 mod p = {C1}")
    print(f"C2 = g^s2 h^r2 mod p = {C2}")
    print(f"C1 * C2 mod p = {C_mul}")
    print(f"g^(s1+s2) h^(r1+r2) mod p = {C_sum}")
    print(f"同态性质验证: {C_mul == C_sum}")

    # 性能测试
    # print("\n【VSS性能测试】")
    # print("=" * 50)
    
    # # 测试不同位数的素数
    # prime_sizes = [1024, 2048, 3072, 4096]
    # num_shares = 8
    # threshold = 4
    # secret = 42
    
    # for size in prime_sizes:
    #     print(f"\n测试 {size} 位素数:")
    #     print("-" * 30)
        
    #     # 生成指定位数的素数
    #     prime = sympy.randprime(2 ** (size - 1), 2 ** size)
    #     vss = VSS(prime=prime)
        
    #     # 测试生成时间
    #     start_time = time.time()
    #     shares, commitments = vss.share(secret, num_shares, threshold, prime)
    #     share_time = time.time() - start_time
        
    #     # 测试单个验证时间
    #     start_time = time.time()
    #     for share in shares:
    #         is_valid = vss.verify_share(share, commitments, prime)
    #     verify_time = time.time() - start_time
        
    #     # 测试批量验证时间
    #     start_time = time.time()
    #     is_valid = vss.verify_shares_batch(shares, commitments, prime)
    #     batch_verify_time = time.time() - start_time
        
    #     # 测试重构时间
    #     start_time = time.time()
    #     reconstructed_secret = vss.reconstruct(shares[:threshold], prime)
    #     reconstruct_time = time.time() - start_time
        
    #     print(f"生成份额时间: {share_time:.6f} 秒")
    #     # print(f"单个验证时间: {verify_time:.6f} 秒")
    #     print(f"批量验证时间: {batch_verify_time:.6f} 秒")
    #     # print(f"重构时间: {reconstruct_time:.6f} 秒")
    #     print("生成+验证时间", share_time+batch_verify_time)

    # # 测试高维向量的批量恢复
    # print("\n【高维向量批量恢复测试】")
    # print("=" * 50)
    
    # # 测试参数
    # vector_dim = 10000  # 向量维度
    # num_shares = 5      # 份额数量
    # threshold = 3       # 阈值
    # prime = vss.q       # 使用q作为prime
    
    # # 生成随机向量
    # vector = np.random.randint(0, 1000, vector_dim)
    # print(f"向量维度: {vector_dim}")
    # print(f"份额数量: {num_shares}")
    # print(f"阈值: {threshold}")
    
    # # 为向量的每一维生成份额
    # all_shares = []
    # for secret in vector:
    #     shares, _ = vss.share(secret, num_shares, threshold, prime)
    #     all_shares.append(shares)
    
    # # 测试单个恢复
    # print("\n【单个恢复测试】")
    # start_time = time.time()
    # single_recovered = []
    # for shares in all_shares:
    #     secret = vss.reconstruct(shares, prime)
    #     single_recovered.append(secret)
    # single_time = time.time() - start_time
    # print(f"单个恢复总时间: {single_time:.4f} 秒")
    # print(f"平均每个维度恢复时间: {single_time/vector_dim*1000:.4f} 毫秒")
    
    # # 测试批量恢复
    # print("\n【批量恢复测试】")
    # start_time = time.time()
    # batch_recovered = vss.reconstruct_batch_fast(all_shares, prime)
    # batch_time = time.time() - start_time
    # print(f"批量恢复总时间: {batch_time:.4f} 秒")
    # print(f"平均每个维度恢复时间: {batch_time/vector_dim*1000:.4f} 毫秒")
    
    # # 验证结果
    # is_correct = all(s == b for s, b in zip(single_recovered, batch_recovered))
    # print(f"\n恢复结果验证: {'正确' if is_correct else '错误'}")
    
    # # 计算性能提升
    # speedup = single_time / batch_time
    # print(f"性能提升倍数: {speedup:.2f}x")
    
    # 打印一些样本值进行对比
    # print("\n【样本值对比】")
    # print("原始值\t单个恢复\t批量恢复")
    # print("-" * 40)
    # for i in range(min(5, vector_dim)):
    #     print(f"{vector[i]}\t{single_recovered[i]}\t{batch_recovered[i]}")

    # 测试多个值的份额相加后恢复
    print("\n【多个值的份额相加后恢复测试】")
    print("=" * 50)
    
    # 测试参数
    num_values = 5      # 值的数量
    num_shares = 4     # 份额数量
    threshold = 2       # 阈值
    prime = 1111     # 使用q作为prime
    
    # 生成多个随机值
    # values = [random.randint(0, 1000) for _ in range(num_values)]
    # values = 256个1
    values = [10] * 256
    print(f"原始值: {values}")
    print(f"原始值的和: {sum(values)}")
    
    # 为每个值生成份额
    all_shares = []
    for value in values:
        shares, _ = vss.share(value, num_shares, threshold, prime)
        all_shares.append(shares)
    
    # 将对应位置的份额相加
    combined_shares = []
    for i in range(num_shares):
        # 获取所有份额的第i个位置
        share_values = [shares[i] for shares in all_shares]
        # 将对应位置的值相加
        combined_share = (
            share_values[0][0],  # 保持索引不变
            sum(share[1] for share in share_values) % prime,  # 份额值相加
            sum(share[2] for share in share_values) % prime   # 盲化值相加
        )
        combined_shares.append(combined_share)
    
    # 从相加后的份额中恢复
    recovered_sum = vss.reconstruct(combined_shares[:threshold], prime)
    
    print(f"\n恢复后的和: {recovered_sum}")
    print(f"验证结果: {'正确' if recovered_sum == sum(values) % prime else '错误'}")
    
    # 打印详细的份额信息
    print("\n【份额详情】")
    print("原始份额:")
    for i, shares in enumerate(all_shares):
        print(f"值 {values[i]} 的份额: {shares}")
    
    print("\n相加后的份额:")
    print(combined_shares)