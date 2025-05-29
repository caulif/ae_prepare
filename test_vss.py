from util.crypto.secretsharing.vss import VSS
import random

def test_vss():
    # 创建VSS实例
    vss = VSS()
    
    # 测试参数
    secret = 42  # 要分享的秘密
    num_shares = 5  # 生成的份额数量
    threshold = 3   # 恢复秘密所需的最小份额数
    prime = vss.q   # 使用q作为素数
    
    print("【VSS测试】")
    print("=" * 50)
    print(f"原始秘密: {secret}")
    print(f"份额数量: {num_shares}")
    print(f"阈值: {threshold}")
    
    # 生成份额
    shares, commitments = vss.share(secret, num_shares, threshold, prime)
    
    # 打印生成的份额
    print("\n【生成的份额】")
    for i, (x, f_x, r_x) in enumerate(shares):
        print(f"份额 {i+1}: (x={x}, f(x)={f_x}, r(x)={r_x})")
    
    # 验证份额
    print("\n【份额验证】")
    for i, share in enumerate(shares):
        is_valid = vss.verify_share(share, commitments, prime)
        print(f"份额 {i+1} 验证结果: {'有效' if is_valid else '无效'}")
    
    # 使用阈值数量的份额恢复秘密
    print("\n【秘密恢复】")
    recovered_secret = vss.reconstruct(shares[:threshold], prime)
    print(f"恢复的秘密: {recovered_secret}")
    print(f"恢复是否成功: {'是' if recovered_secret == secret else '否'}")
    
    # 测试批量验证
    print("\n【批量验证】")
    is_valid = vss.verify_shares_batch(shares, commitments, prime)
    print(f"批量验证结果: {'有效' if is_valid else '无效'}")

if __name__ == "__main__":
    test_vss() 