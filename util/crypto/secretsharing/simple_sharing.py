# -*- coding: utf-8 -*-
"""
    Simple Secret Sharing
    ~~~~~

    实现简单的秘密分享和重建功能。
"""

import random

def share_secret(secret, num_shares, threshold, prime=None):
    """
    使用Shamir秘密分享方案分享秘密。
    
    Args:
        secret: 要分享的秘密（整数）
        num_shares: 要生成的份额数量
        threshold: 重建秘密所需的最小份额数量
        prime: 用于计算的素数。如果为None，将自动生成一个合适的素数
        
    Returns:
        shares: 份额列表，每个份额是一个元组 (x, y)
    """
    if threshold > num_shares:
        raise ValueError("阈值不能大于份额数量！")
    if prime is None:
        # 使用一个足够大的素数
        prime = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
            
    # 确保secret在prime范围内
    secret = secret % prime
    
    # 生成随机多项式系数
    coefficients = [secret]  # 第一个系数是秘密值
    for _ in range(threshold - 1):
        coefficients.append(random.randint(0, prime - 1))
    
    # 计算多项式在点1到num_shares处的值
    points = []
    for x in range(1, num_shares + 1):
        y = 0
        for i, coef in enumerate(coefficients):
            y = (y + coef * pow(x, i, prime)) % prime
        points.append((x, y))
    
    return points

def reconstruct_secret(shares, prime):
    """
    从份额中重建秘密。
    
    Args:
        shares: 份额列表，每个份额是一个元组 (x, y)
        prime: 用于计算的素数
        
    Returns:
        secret: 重建的秘密
    """
    if len(shares) < 2:
        raise ValueError("至少需要2个份额才能重建秘密")
    
    # 使用拉格朗日插值重建秘密
    x_coords = [x for x, _ in shares]
    y_coords = [y for _, y in shares]
    
    def basis_polynomial(j, x):
        numerator = denominator = 1
        for m in range(len(x_coords)):
            if m != j:
                numerator = (numerator * (x - x_coords[m])) % prime
                denominator = (denominator * (x_coords[j] - x_coords[m])) % prime
        return (numerator * pow(denominator, -1, prime)) % prime
    
    # 计算在x=0处的值
    secret = 0
    for j in range(len(shares)):
        secret = (secret + y_coords[j] * basis_polynomial(j, 0)) % prime
    
    return secret 