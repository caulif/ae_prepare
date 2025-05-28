from Cryptodome.PublicKey import ECC
import os

def generate_ecc_key_pair(node_id):
    """为指定节点生成ECC密钥对"""
    # 生成256位的ECC密钥对
    key = ECC.generate(curve='P-256')
    
    # 保存私钥
    private_key_path = f'node{node_id}.pem'
    with open(private_key_path, 'wb') as f:
        f.write(key.export_key(format='PEM').encode('utf-8'))
    
    # 保存公钥
    public_key_path = f'node{node_id}_public.pem'
    with open(public_key_path, 'wb') as f:
        f.write(key.public_key().export_key(format='PEM').encode('utf-8'))

def main():
    # 确保pki_files目录存在
    if not os.path.exists('pki_files'):
        os.makedirs('pki_files')
    
    # 切换到pki_files目录
    os.chdir('pki_files')
    
    # 为服务器生成密钥对
    generate_ecc_key_pair(0)
    
    # 为客户端生成密钥对
    for i in range(1, 4100):
        generate_ecc_key_pair(i)
    
    print("密钥对生成完成！")

if __name__ == "__main__":
    main()

