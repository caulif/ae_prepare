# -*- coding: utf-8 -*-
"""
测试VSS在高维向量上的性能
"""

import time
import numpy as np
from vss import VSS

def test_vector_sharing_recovery():
    # 创建VSS实例
    vss = VSS()
    
    # 测试参数
    vector_dim = 10000  # 向量维度
    num_shares = 5      # 份额数量
    threshold = 3       # 阈值
    prime = vss.q       # 使用q作为prime
    
    print("\n【高维向量秘密分享和恢复测试】")
    print("=" * 50)
    print(f"向量维度: {vector_dim}")
    print(f"份额数量: {num_shares}")
    print(f"阈值: {threshold}")
    
    # 生成随机向量
    vector = np.random.randint(0, 1000, vector_dim)
    
    # 测试分享时间
    print("\n【分享测试】")
    start_time = time.time()
    all_shares = []
    for secret in vector:
        shares, _ = vss.share(secret, num_shares, threshold, prime)
        all_shares.append(shares)
    share_time = time.time() - start_time
    print(f"分享总时间: {share_time:.4f} 秒")
    print(f"平均每个维度分享时间: {share_time/vector_dim*1000:.4f} 毫秒")
    
    # 测试单个恢复
    print("\n【单个恢复测试】")
    start_time = time.time()
    single_recovered = []
    for shares in all_shares:
        secret = vss.reconstruct(shares, prime)
        single_recovered.append(secret)
    single_time = time.time() - start_time
    print(f"单个恢复总时间: {single_time:.4f} 秒")
    print(f"平均每个维度恢复时间: {single_time/vector_dim*1000:.4f} 毫秒")
    
    # 测试批量恢复
    print("\n【批量恢复测试】")
    start_time = time.time()
    batch_recovered = vss.reconstruct_batch_fast(all_shares, prime)
    batch_time = time.time() - start_time
    print(f"批量恢复总时间: {batch_time:.4f} 秒")
    print(f"平均每个维度恢复时间: {batch_time/vector_dim*1000:.4f} 毫秒")
    
    # 验证结果
    is_correct = all(s == b for s, b in zip(single_recovered, batch_recovered))
    print(f"\n恢复结果验证: {'正确' if is_correct else '错误'}")
    
    # 计算性能提升
    speedup = single_time / batch_time
    print(f"批量恢复性能提升倍数: {speedup:.2f}x")
    
    # 打印一些样本值进行对比
    print("\n【样本值对比】")
    print("原始值\t单个恢复\t批量恢复")
    print("-" * 40)
    for i in range(min(5, vector_dim)):
        print(f"{vector[i]}\t{single_recovered[i]}\t{batch_recovered[i]}")

if __name__ == "__main__":
    test_vector_sharing_recovery() 