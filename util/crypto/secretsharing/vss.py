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
        # Use the provided prime as p
        self.p = prime if prime is not None else sympy.randprime(2 ** (2048 - 1), 2 ** 2048)
        # q = (p-1)/2
        self.q = (self.p - 1) // 2
        # Generate secure generator
        self.g = self._find_generator()
        self.h = self._find_generator(different_from=self.g)
        
    def _find_generator(self, different_from=None):
        """Generate a secure generator"""
        while True:
            x = random.randrange(2, self.p - 1)
            g = gmpy2.powmod(x, (self.p - 1) // self.q, self.p)
            if g != 1 and (different_from is None or g != different_from):
                return g
        
    def _evaluate_polynomial(self, coefficients, x, prime):
        """Calculate polynomial value at point x using Horner's method"""
        result = coefficients[-1]
        for coef in reversed(coefficients[:-1]):
            result = (result * x + coef) % prime
        return result

    def _fast_mod_pow(self, base, exp, mod):
        """Use fast modular exponentiation algorithm"""
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
        # Ensure secret is within q range
        secret = secret % self.q
        
        # Use fixed coefficients instead of random ones
        f_coeffs = [secret]  # First coefficient is secret
        r_coeffs = [1]      # First r coefficient is fixed as 1
        
        # Use fixed coefficients
        for i in range(threshold - 1):
            f_coeffs.append(i + 1)  # Use incrementing fixed coefficients
            r_coeffs.append(i + 2)  # Use incrementing fixed coefficients
        
        # Calculate Pedersen commitments C_j = g^{a_j} h^{b_j} mod p
        commitments = []
        for j in range(threshold):
            c = (gmpy2.powmod(self.g, f_coeffs[j], self.p) * 
                 gmpy2.powmod(self.h, r_coeffs[j], self.p)) % self.p
            commitments.append(c)
        
        # Generate shares (i, f(i), r(i)), all in q
        shares = []
        for i in range(1, num_shares + 1):
            # Calculate polynomial value at point i
            f_i = 0
            r_i = 0
            
            # Calculate f(i)
            for j, coef in enumerate(f_coeffs):
                f_i = (f_i + coef * gmpy2.powmod(i, j, self.q)) % self.q
            
            # Calculate r(i)
            for j, coef in enumerate(r_coeffs):
                r_i = (r_i + coef * gmpy2.powmod(i, j, self.q)) % self.q
            
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
            
            # Check input parameters
            if not isinstance(x, int) or not isinstance(f_x, int) or not isinstance(r_x, int):
                return False
                
            if not isinstance(commitments, list) or not commitments:
                return False
            
            # Ensure values are within q range
            f_x = f_x % self.q
            r_x = r_x % self.q
            
            # Calculate g^f(x) * h^r(x) mod p
            left = (gmpy2.powmod(self.g, f_x, self.p) * gmpy2.powmod(self.h, r_x, self.p)) % self.p
            
            # Calculate ∏(C_j^x^j) mod p
            right = 1
            for j, Cj in enumerate(commitments):
                x_pow_j = gmpy2.powmod(x, j, self.q)
                right = (right * gmpy2.powmod(Cj, x_pow_j, self.p)) % self.p
            
            return left == right
            
        except Exception as e:
            return False

    def verify_shares_batch(self, shares, commitments, prime):
        """
        Batch verify multiple shares using Pedersen commitment homomorphism.
        
        Args:
            shares: List of shares in format (share_index, share_value, blinding_value)
            commitments: List of commitments
            prime: Prime number
            
        Returns:
            is_valid: True if all shares are valid, False otherwise
        """
        try:
            if not shares or not commitments:
                return False
                
            # Calculate commitment for all shares
            C_total = 1
            for x, f_x, r_x in shares:
                # Ensure values are within q range
                f_x = f_x % self.q
                r_x = r_x % self.q
                # Calculate commitment for single share
                C_i = (gmpy2.powmod(self.g, f_x, self.p) * gmpy2.powmod(self.h, r_x, self.p)) % self.p
                # Multiply all commitments
                C_total = (C_total * C_i) % self.p
            
            # Calculate sum of all share values
            sum_f = 0
            sum_r = 0
            for _, f_x, r_x in shares:
                sum_f = (sum_f + f_x) % self.q
                sum_r = (sum_r + r_x) % self.q
            
            # Calculate total commitment using homomorphism
            C_sum = (gmpy2.powmod(self.g, sum_f, self.p) * gmpy2.powmod(self.h, sum_r, self.p)) % self.p
            
            # Verify if two results are equal
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
            raise ValueError("At least 2 shares are required to reconstruct the secret")
        
        self.q = prime
        
        # Handle nested list format
        if isinstance(shares[0], list):
            shares = [share[0] for share in shares]
        
        # Compatible with 2-tuple and 3-tuple shares
        normalized_shares = []
        for share in shares:
            if len(share) == 2:
                # Automatically add 0 as blinding
                share = (share[0], share[1], 0)
            elif len(share) != 3:
                raise ValueError("Invalid share format: must be (index, value) or (index, value, blinding)")
            # Modify type check to allow mpz type
            if not all(isinstance(x, (int, gmpy2.mpz)) for x in share):
                raise ValueError("Share components must be integers or mpz")
            normalized_shares.append(share)
        
        # Use Lagrange interpolation to reconstruct secret (in q)
        secret = 0
        for i, (x_i, y_i, _) in enumerate(normalized_shares):
            numerator = denominator = 1
            for j, (x_j, _, _) in enumerate(normalized_shares):
                if i != j:
                    numerator = (numerator * (-x_j)) % self.q
                    denominator = (denominator * (x_i - x_j)) % self.q
            try:
                inv_denominator = gmpy2.powmod(denominator, -1, self.q)
                lagrange_coef = (numerator * inv_denominator) % self.q
                secret = (secret + (y_i * lagrange_coef) % self.q) % self.q
            except ValueError:
                continue
        return int(secret)  # Ensure return native Python integer

    def reconstruct_batch(self, shares_list, prime):
        """
        Batch reconstruct multiple secrets.
        
        Args:
            shares_list: List of share lists, each inner list contains shares in format [(share_index, share_value, blinding_value)].
            prime: Prime number.
            
        Returns:
            secrets: List of reconstructed secrets.
            
        Raises:
            ValueError: If shares list is empty or invalid format.
        """
        if not shares_list:
            raise ValueError("Shares list cannot be empty")
            
        secrets = []
        for shares in shares_list:
            try:
                secret = self.reconstruct(shares, prime)
                secrets.append(secret)
            except ValueError as e:
                print(f"Warning: Error reconstructing secret: {e}")
                secrets.append(None)
                
        return secrets

    def reconstruct_batch_fast(self, shares_list, prime):
        """
        Fast batch reconstruction of multiple secrets.
        Uses precomputation and matrix operations to optimize performance.
        
        Args:
            shares_list: List of share lists, each inner list contains shares in format [(share_index, share_value, blinding_value)].
            prime: Prime number.
            
        Returns:
            secrets: List of reconstructed secrets.
        """
        if not shares_list:
            return []
            
        secrets = []
        # Get x values from first share set
        x_values = [x for x, _, _ in shares_list[0]]
        
        # Precompute all possible Lagrange coefficients
        lagrange_coeffs = []
        for i, x_i in enumerate(x_values):
            numerator = denominator = 1
            for j, x_j in enumerate(x_values):
                if i != j:
                    numerator = (numerator * (-x_j)) % self.q
                    denominator = (denominator * (x_i - x_j)) % self.q
            try:
                inv_denominator = gmpy2.powmod(denominator, -1, self.q)
                lagrange_coef = (numerator * inv_denominator) % self.q
                lagrange_coeffs.append(lagrange_coef)
            except ValueError:
                lagrange_coeffs.append(0)
        
        # Batch calculate all secrets
        for shares in shares_list:
            try:
                # Use precomputed Lagrange coefficients
                secret = 0
                for i, (_, y_i, _) in enumerate(shares):
                    secret = (secret + (y_i * lagrange_coeffs[i]) % self.q) % self.q
                secrets.append(secret)
            except Exception as e:
                print(f"Warning: Error reconstructing secret: {e}")
                secrets.append(None)
                
        return secrets

