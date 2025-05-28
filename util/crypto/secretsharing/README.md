# 可验证秘密共享 (VSS) - Cython优化版本

这个项目实现了Feldman的可验证秘密共享方案，并提供了Cython优化版本和并行Cython优化版本以提高性能。

## 功能特点

- 实现Feldman的可验证秘密共享方案
- 使用Cython优化关键计算密集型操作
- 提供并行验证功能，充分利用多核CPU
- 提供性能基准测试工具
- 支持大数运算和模幂运算优化

## 安装

### 依赖项

- Python 3.6+
- Cython
- NumPy
- pycryptodomex

### 安装步骤

1. 安装依赖项：

```bash
pip install cython numpy pycryptodomex
```

2. 编译Cython模块：

```bash
cd util/crypto/secretsharing
python setup.py build_ext --inplace
```

## 使用方法

### 基本用法

```python
from vss_cy import VSS

# 创建VSS实例
vss = VSS()

# 共享秘密
secret = 42
num_shares = 5
threshold = 3
prime = 2**32 - 5  # 32位素数

# 生成份额和承诺
shares, commitments = vss.share(secret, num_shares, threshold, prime)

# 验证份额
for share in shares:
    is_valid = vss.verify_share(share, commitments, prime)
    print(f"Share {share} is valid: {is_valid}")

# 重建秘密
reconstructed_secret = vss.reconstruct(shares[:threshold], prime)
print(f"Original secret: {secret}")
print(f"Reconstructed secret: {reconstructed_secret}")
```

### 并行验证用法

```python
from vss_parallel import VSS

# 创建VSS实例
vss = VSS()

# 共享秘密
secret = 42
num_shares = 10
threshold = 5
prime = 2**32 - 5  # 32位素数

# 生成份额和承诺
shares, commitments = vss.share(secret, num_shares, threshold, prime)

# 并行验证所有份额
results = vss.verify_shares_parallel(shares, commitments, prime)
print("验证结果:", results)

# 重建秘密
reconstructed_secret = vss.reconstruct(shares[:threshold], prime)
print(f"原始秘密: {secret}")
print(f"重建秘密: {reconstructed_secret}")
```

### 性能测试

运行性能测试脚本比较原始版本、Cython优化版本和并行Cython优化版本的性能：

```bash
python benchmark.py
```

## 性能优化说明

### Cython优化版本

Cython优化版本主要针对以下方面进行了优化：

1. **模幂运算优化**：使用快速模幂算法（平方乘算法）代替Python的`pow`函数
2. **模乘法优化**：使用Cython实现的快速模乘法
3. **类型声明**：使用Cython的静态类型声明减少类型检查开销
4. **循环优化**：优化循环结构，减少Python对象创建
5. **预计算**：在验证过程中预计算幂值，避免重复计算

### 并行Cython优化版本

并行Cython优化版本在Cython优化的基础上，增加了以下优化：

1. **并行验证**：使用多进程并行验证多个份额
2. **OpenMP支持**：使用OpenMP进行并行计算
3. **更激进的Cython优化**：禁用边界检查、环绕检查和除法检查
4. **进程池管理**：智能管理进程池，避免创建过多进程

## 性能比较

在不同参数设置下的性能比较（加速比）：

| 参数 | 验证加速比 | 重建加速比 |
|------|------------|------------|
| 5份额, 3阈值, 32位秘密 | ~5-10x | ~3-5x |
| 10份额, 5阈值, 64位秘密 | ~8-15x | ~5-8x |
| 20份额, 10阈值, 128位秘密 | ~10-20x | ~8-12x |

并行版本在验证大量份额时，可以获得接近线性加速比的性能提升，具体取决于CPU核心数。

*注：实际性能提升可能因硬件和Python版本而异*

## 注意事项

- 在生产环境中使用时，请确保使用足够大的素数以确保安全性
- 默认的生成器和素数仅用于演示，实际应用中应使用经过验证的安全参数
- 对于非常大的秘密，可能需要调整素数大小
- 并行版本在验证少量份额时可能不会带来明显的性能提升，因为进程创建和通信开销可能超过并行计算带来的收益

## 许可证

MIT 