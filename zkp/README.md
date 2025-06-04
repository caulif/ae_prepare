# Python Bulletproofs 实现

这是一个用 Python 实现的 Bulletproofs 零知识证明系统。Bulletproofs 是一种高效的零知识证明协议，特别适用于范围证明（Range Proofs）和聚合范围证明（Aggregated Range Proofs）。

## 项目结构

- `utils/`: 工具函数和辅助模块
- `rangeproofs/`: 范围证明相关实现
- `innerproduct/`: 内积证明实现
- `pippenger/`: 快速标量乘法实现
- `tests/`: 测试用例

## 详细函数说明

### 1. 工具模块 (utils)

#### 1.1 椭圆曲线工具 (utils/utils.py)

##### 1.1.1 ModP 类
```python
class ModP:
    """表示模 p 的整数类"""
    
    def __init__(self, x: int, p: int):
        """
        初始化一个模 p 的整数
        参数:
            x: 整数值
            p: 模数
        """
```

使用示例：
```python
from utils.utils import ModP
from fastecdsa.curve import secp256k1

# 创建模 p 的整数
p = secp256k1.q
x = ModP(5, p)
y = ModP(3, p)

# 基本运算
z = x + y  # 加法
z = x - y  # 减法
z = x * y  # 乘法
z = x.inv()  # 模逆
```

##### 1.1.2 mod_hash
```python
def mod_hash(msg: bytes, p: int, non_zero: bool = True) -> ModP:
    """
    将消息哈希到有限域
    参数:
        msg: 要哈希的消息（字节）
        p: 模数
        non_zero: 是否要求结果非零
    返回:
        ModP: 哈希结果
    """
```

使用示例：
```python
from utils.utils import mod_hash
from fastecdsa.curve import secp256k1

# 哈希消息到有限域
msg = b"test message"
p = secp256k1.q
h = mod_hash(msg, p)
print(f"哈希结果: {h}")
```

##### 1.1.3 点转换函数
```python
def point_to_bytes(g: Point) -> bytes:
    """将椭圆曲线点转换为字节"""
    
def bytes_to_point(b: bytes) -> Point:
    """将字节转换为椭圆曲线点"""
    
def point_to_b64(g: Point) -> bytes:
    """将椭圆曲线点转换为Base64编码"""
    
def b64_to_point(s: bytes) -> Point:
    """将Base64编码转换为椭圆曲线点"""
```

使用示例：
```python
from utils.utils import point_to_bytes, bytes_to_point, point_to_b64, b64_to_point
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

# 创建椭圆曲线点
g = secp256k1.G

# 转换示例
bytes_data = point_to_bytes(g)
point = bytes_to_point(bytes_data)
b64_data = point_to_b64(g)
point2 = b64_to_point(b64_data)

assert point == g
assert point2 == g
```

#### 1.2 椭圆曲线哈希 (utils/elliptic_curve_hash.py)

##### 1.2.1 elliptic_hash
```python
def elliptic_hash(msg: bytes, curve) -> Point:
    """
    将消息哈希到椭圆曲线上的点
    参数:
        msg: 要哈希的消息（字节）
        curve: 椭圆曲线对象
    返回:
        Point: 椭圆曲线上的点
    """
```

使用示例：
```python
from utils.elliptic_curve_hash import elliptic_hash
from fastecdsa.curve import secp256k1

# 哈希消息到椭圆曲线点
msg = b"test message"
point = elliptic_hash(msg, secp256k1)
print(f"椭圆曲线点: {point}")
```

#### 1.3 承诺方案 (utils/commitments.py)

##### 1.3.1 commitment
```python
def commitment(g: Point, h: Point, v: ModP, gamma: ModP) -> Point:
    """
    创建 Pedersen 承诺
    参数:
        g: 生成元1
        h: 生成元2
        v: 要承诺的值
        gamma: 随机盲化因子
    返回:
        Point: 承诺点
    """
```

使用示例：
```python
from utils.commitments import commitment
from utils.elliptic_curve_hash import elliptic_hash
from utils.utils import ModP
from fastecdsa.curve import secp256k1

# 创建承诺
g = elliptic_hash(b"g", secp256k1)
h = elliptic_hash(b"h", secp256k1)
v = ModP(5, secp256k1.q)
gamma = ModP(3, secp256k1.q)

commit = commitment(g, h, v, gamma)
print(f"承诺点: {commit}")
```

### 2. 范围证明 (rangeproofs)

#### 2.1 聚合范围证明

##### 2.1.1 AggregNIRangeProver
```python
class AggregNIRangeProver:
    def __init__(self, vs: List[ModP], n: int, g: Point, h: Point, 
                 gs: List[Point], hs: List[Point], gammas: List[ModP], 
                 u: Point, curve, seed: bytes):
        """
        初始化聚合范围证明的证明者
        参数:
            vs: 要证明的值列表
            n: 范围大小（2^n）
            g, h: 生成元
            gs, hs: 生成元列表
            gammas: 盲化因子列表
            u: 额外的生成元
            curve: 椭圆曲线
            seed: 随机种子
        """
    
    def prove(self) -> dict:
        """
        生成范围证明
        返回:
            dict: 包含证明信息的字典
        """
```

##### 2.1.2 AggregRangeVerifier
```python
class AggregRangeVerifier:
    def __init__(self, Vs: List[Point], g: Point, h: Point, 
                 gs: List[Point], hs: List[Point], u: Point, proof: dict):
        """
        初始化聚合范围证明的验证者
        参数:
            Vs: 承诺列表
            g, h: 生成元
            gs, hs: 生成元列表
            u: 额外的生成元
            proof: 证明信息
        """
    
    def verify(self) -> bool:
        """
        验证范围证明
        返回:
            bool: 验证结果
        """
```

使用示例：
```python
from fastecdsa.curve import secp256k1
from utils.utils import ModP
from utils.elliptic_curve_hash import elliptic_hash
from utils.commitments import commitment
from rangeproofs import AggregNIRangeProver, AggregRangeVerifier
import os

# 设置参数
CURVE = secp256k1
p = secp256k1.q
m = 4  # 要证明的值的数量
n = 16  # 范围大小（2^n）
seeds = [os.urandom(10) for _ in range(7)]

# 生成要证明的值
vs = [ModP(randint(0, 2**16 - 1), p) for _ in range(m)]

# 生成生成元
gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n * m)]
hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n * m)]
g = elliptic_hash(seeds[2], CURVE)
h = elliptic_hash(seeds[3], CURVE)
u = elliptic_hash(seeds[4], CURVE)

# 生成承诺
gammas = [mod_hash(seeds[5], p) for _ in range(m)]
Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]

# 创建证明
prover = AggregNIRangeProver(vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6])
proof = prover.prove()

# 验证证明
verifier = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
assert verifier.verify()
```

## 测试方法

1. 运行所有测试：
```bash
./run_tests.sh
```

2. 运行特定测试：
```bash
python -m unittest tests/test_utils.py
python -m unittest tests/test_aggreg_rangeproofs.py
```

## 注意事项

1. 所有数值计算都在有限域中进行
2. 使用安全的随机数生成器
3. 保护私钥和敏感信息
4. 验证所有输入的有效性

## 性能优化

1. 使用 Pippenger 算法优化标量乘法
2. 支持批量验证
3. 证明大小与范围大小对数相关

## 安全注意事项

1. 确保使用安全的随机数生成器
2. 验证所有输入的有效性
3. 使用安全的哈希函数
4. 保护私钥和敏感信息 