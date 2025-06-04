from Cryptodome.PublicKey import ECC
import os

def generate_ecc_key_pair(node_id):
    """Generate ECC key pair for specified node"""
    # Generate 256-bit ECC key pair
    key = ECC.generate(curve='P-256')
    
    # Save private key
    private_key_path = f'node{node_id}.pem'
    with open(private_key_path, 'wb') as f:
        f.write(key.export_key(format='PEM').encode('utf-8'))
    
    # Save public key
    public_key_path = f'node{node_id}_public.pem'
    with open(public_key_path, 'wb') as f:
        f.write(key.public_key().export_key(format='PEM').encode('utf-8'))

def main():
    # Ensure pki_files directory exists
    if not os.path.exists('pki_files'):
        os.makedirs('pki_files')
    
    # Change to pki_files directory
    os.chdir('pki_files')
    
    # Generate key pair for server
    generate_ecc_key_pair(0)
    
    # Generate key pairs for clients
    for i in range(1, 512):
        generate_ecc_key_pair(i)
    
    print("Key pairs generation completed!")

if __name__ == "__main__":
    main()

