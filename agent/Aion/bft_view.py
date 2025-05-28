import time
import logging
import dill
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import ECC
import os

@dataclass
class ViewChangeMessage:
    view: int
    node_id: int
    last_checkpoint: int
    prepared_messages: List[dict]
    signature: Optional[str] = None
    timestamp: float = 0.0

class ViewChangeProtocol:
    def __init__(self, node_id: int, total_nodes: int):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.current_view = 0
        self.view_change_timeout = 5  # 秒
        self.view_change_timer = None
        self.new_view_proposals: Dict[int, ViewChangeMessage] = {}
        self.last_checkpoint = 0
        self.logger = logging.getLogger(__name__)
        
        # 加载节点的密钥对
        self._load_keys()
        
    def _load_keys(self):
        """加载节点的密钥对"""
        try:
            # 从文件加载私钥
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            if not os.path.exists(private_key_path):
                self.logger.warning(f"Private key file not found: {private_key_path}")
                # 生成新的密钥对
                self._generate_keys()
                return
                
            with open(private_key_path, 'rb') as f:
                self.private_key = ECC.import_key(f.read())
                
            # 从文件加载公钥
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            if not os.path.exists(public_key_path):
                self.logger.warning(f"Public key file not found: {public_key_path}")
                # 生成新的密钥对
                self._generate_keys()
                return
                
            with open(public_key_path, 'rb') as f:
                self.public_key = ECC.import_key(f.read())
                
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            # 生成新的密钥对
            self._generate_keys()
            
    def _generate_keys(self):
        """生成新的ECC密钥对"""
        try:
            # 生成256位的ECC密钥对
            key = ECC.generate(curve='P-256')
            self.private_key = key
            self.public_key = key.public_key()
            
            # 确保pki_files目录存在
            if not os.path.exists('pki_files'):
                os.makedirs('pki_files')
            
            # 保存私钥
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.export_key(format='PEM'))
            
            # 保存公钥
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.export_key(format='PEM'))
                
            self.logger.info(f"Generated new key pair for node {self.node_id}")
        except Exception as e:
            self.logger.error(f"Failed to generate keys: {e}")
            raise
        
    def start_view_change(self):
        """启动视图切换"""
        self.current_view += 1
        self.logger.info(f"Starting view change to view {self.current_view}")
        view_change_msg = self._broadcast_view_change()
        self._start_view_change_timer()
        return view_change_msg
        
    def _broadcast_view_change(self) -> ViewChangeMessage:
        """广播视图切换请求"""
        view_change_msg = ViewChangeMessage(
            view=self.current_view,
            node_id=self.node_id,
            last_checkpoint=self.last_checkpoint,
            prepared_messages=self._get_prepared_messages(),
            timestamp=time.time()
        )
        
        # 签名消息
        view_change_msg.signature = self._sign_message(view_change_msg)
        return view_change_msg
        
    def _sign_message(self, msg: ViewChangeMessage) -> str:
        """签名消息"""
        # 序列化消息内容
        msg_data = {
            'view': msg.view,
            'node_id': msg.node_id,
            'last_checkpoint': msg.last_checkpoint,
            'prepared_messages': msg.prepared_messages,
            'timestamp': msg.timestamp
        }
        serialized_data = dill.dumps(msg_data)
        
        # 计算消息哈希
        hash_obj = SHA256.new(serialized_data)
        
        # 使用ECC私钥签名
        signer = DSS.new(self.private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        
        return signature.hex()
        
    def _verify_signature(self, msg: ViewChangeMessage, public_key: ECC.EccKey) -> bool:
        """验证消息签名"""
        try:
            # 序列化消息内容
            msg_data = {
                'view': msg.view,
                'node_id': msg.node_id,
                'last_checkpoint': msg.last_checkpoint,
                'prepared_messages': msg.prepared_messages,
                'timestamp': msg.timestamp
            }
            serialized_data = dill.dumps(msg_data)
            
            # 计算消息哈希
            hash_obj = SHA256.new(serialized_data)
            
            # 使用ECC公钥验证签名
            verifier = DSS.new(public_key, 'fips-186-3')
            verifier.verify(hash_obj, bytes.fromhex(msg.signature))
            return True
        except Exception as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False
        
    def handle_view_change(self, msg: ViewChangeMessage) -> bool:
        """处理视图切换消息"""
        # 验证消息签名
        try:
            with open(f'pki_files/node{msg.node_id}_public.pem', 'rb') as f:
                sender_public_key = ECC.import_key(f.read())
            if not self._verify_signature(msg, sender_public_key):
                self.logger.warning(f"Invalid signature in view change message from node {msg.node_id}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to verify view change message: {e}")
            return False
            
        if msg.view > self.current_view:
            self.new_view_proposals[msg.node_id] = msg
            self.logger.info(f"Received view change proposal for view {msg.view} from node {msg.node_id}")
            
            # 检查是否收到足够的视图切换提议
            if len(self.new_view_proposals) >= (self.total_nodes // 2 + 1):
                self.logger.info(f"Received enough view change proposals for view {msg.view}")
                return True
        return False
        
    def _get_prepared_messages(self) -> List[dict]:
        """获取已准备的消息"""
        # 实现获取已准备消息的逻辑
        return []
        
    def _start_view_change_timer(self):
        """启动视图切换定时器"""
        self.view_change_timer = time.time()
        
    def check_view_change_timeout(self) -> bool:
        """检查视图切换是否超时"""
        if self.view_change_timer is None:
            return False
        return time.time() - self.view_change_timer > self.view_change_timeout

class CheckpointProtocol:
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.checkpoint_interval = 100  # 检查点间隔
        self.last_checkpoint = 0
        self.checkpoint_state: Dict[int, dict] = {}
        self.stable_checkpoints: Dict[int, dict] = {}
        self.logger = logging.getLogger(__name__)
        
        # 加载节点的密钥对
        self._load_keys()
        
    def _load_keys(self):
        """加载节点的密钥对"""
        try:
            # 从文件加载私钥
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            if not os.path.exists(private_key_path):
                self.logger.warning(f"Private key file not found: {private_key_path}")
                # 生成新的密钥对
                self._generate_keys()
                return
                
            with open(private_key_path, 'rb') as f:
                self.private_key = ECC.import_key(f.read())
                
            # 从文件加载公钥
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            if not os.path.exists(public_key_path):
                self.logger.warning(f"Public key file not found: {public_key_path}")
                # 生成新的密钥对
                self._generate_keys()
                return
                
            with open(public_key_path, 'rb') as f:
                self.public_key = ECC.import_key(f.read())
                
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            # 生成新的密钥对
            self._generate_keys()
            
    def _generate_keys(self):
        """生成新的ECC密钥对"""
        try:
            # 生成256位的ECC密钥对
            key = ECC.generate(curve='P-256')
            self.private_key = key
            self.public_key = key.public_key()
            
            # 确保pki_files目录存在
            if not os.path.exists('pki_files'):
                os.makedirs('pki_files')
            
            # 保存私钥
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.export_key(format='PEM'))
            
            # 保存公钥
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.export_key(format='PEM'))
                
            self.logger.info(f"Generated new key pair for node {self.node_id}")
        except Exception as e:
            self.logger.error(f"Failed to generate keys: {e}")
            raise
        
    def create_checkpoint(self, state: dict) -> dict:
        """创建检查点"""
        checkpoint_number = self.last_checkpoint + self.checkpoint_interval
        checkpoint = {
            'number': checkpoint_number,
            'state': state,
            'digest': self._calculate_digest(state),
            'timestamp': time.time(),
            'node_id': self.node_id
        }
        
        # 签名检查点
        checkpoint['signature'] = self._sign_checkpoint(checkpoint)
        
        self.checkpoint_state[checkpoint_number] = checkpoint
        self.last_checkpoint = checkpoint_number
        self.logger.info(f"Created checkpoint {checkpoint_number}")
        return checkpoint
        
    def _sign_checkpoint(self, checkpoint: dict) -> str:
        """签名检查点"""
        # 序列化检查点内容
        checkpoint_data = {
            'number': checkpoint['number'],
            'state': checkpoint['state'],
            'digest': checkpoint['digest'],
            'timestamp': checkpoint['timestamp'],
            'node_id': checkpoint['node_id']
        }
        serialized_data = dill.dumps(checkpoint_data)
        
        # 计算哈希
        hash_obj = SHA256.new(serialized_data)
        
        # 使用ECC私钥签名
        signer = DSS.new(self.private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        
        return signature.hex()
        
    def verify_checkpoint(self, checkpoint: dict) -> bool:
        """验证检查点"""
        # 验证检查点号
        if checkpoint['number'] % self.checkpoint_interval != 0:
            self.logger.warning(f"Invalid checkpoint number: {checkpoint['number']}")
            return False
            
        # 验证摘要
        if checkpoint['digest'] != self._calculate_digest(checkpoint['state']):
            self.logger.warning("Invalid checkpoint digest")
            return False
            
        # 验证签名
        try:
            with open(f'pki_files/node{checkpoint["node_id"]}_public.pem', 'rb') as f:
                sender_public_key = ECC.import_key(f.read())
                
            # 序列化检查点内容
            checkpoint_data = {
                'number': checkpoint['number'],
                'state': checkpoint['state'],
                'digest': checkpoint['digest'],
                'timestamp': checkpoint['timestamp'],
                'node_id': checkpoint['node_id']
            }
            serialized_data = dill.dumps(checkpoint_data)
            
            # 计算哈希
            hash_obj = SHA256.new(serialized_data)
            
            # 使用ECC公钥验证签名
            verifier = DSS.new(sender_public_key, 'fips-186-3')
            verifier.verify(hash_obj, bytes.fromhex(checkpoint['signature']))
            return True
        except Exception as e:
            self.logger.error(f"Checkpoint verification failed: {e}")
            return False
        
    def stabilize_checkpoint(self, checkpoint_number: int):
        """稳定检查点"""
        if checkpoint_number in self.checkpoint_state:
            self.stable_checkpoints[checkpoint_number] = self.checkpoint_state[checkpoint_number]
            self._cleanup_old_checkpoints(checkpoint_number)
            self.logger.info(f"Stabilized checkpoint {checkpoint_number}")
            
    def _calculate_digest(self, state: dict) -> str:
        """计算状态的摘要"""
        # 序列化状态
        serialized_state = dill.dumps(state)
        # 计算哈希
        return SHA256.new(serialized_state).hexdigest()
        
    def _cleanup_old_checkpoints(self, current_checkpoint: int):
        """清理旧的检查点"""
        # 保留最近的几个检查点，删除其他的
        to_keep = 3
        checkpoints_to_delete = sorted(self.stable_checkpoints.keys())[:-to_keep]
        for checkpoint in checkpoints_to_delete:
            del self.stable_checkpoints[checkpoint]
            self.logger.info(f"Cleaned up old checkpoint {checkpoint}") 