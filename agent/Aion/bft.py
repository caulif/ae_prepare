import time
import logging
import dill
import os
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from enum import Enum
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import ECC
from Cryptodome.Util.number import long_to_bytes, bytes_to_long

class BFTPhase(Enum):
    PREPARE = 1
    PRECOMMIT = 2
    COMMIT = 3

@dataclass
class BFTMessage:
    type: str
    value: Any
    phase: BFTPhase
    node_id: int
    signature: Optional[str] = None
    counter: Optional[int] = None
    view: int = 0
    sequence: int = 0
    timestamp: float = 0.0

class BFTProtocol:
    def __init__(self, node_id: int, total_nodes: int, f: int):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.f = f  # Maximum number of faulty nodes
        self.messages: Dict[str, List[BFTMessage]] = {}
        self.votes: Dict[str, int] = {}
        self.phase = 0
        self.proposed_value = None
        self.decided_value = None
        self.logger = logging.getLogger(__name__)
        self.view = 0
        self.sequence = 0
        self.prepared_values: Dict[int, Set[Any]] = {}
        self.committed_values: Dict[int, Set[Any]] = {}
        self.timeout = 5  # Timeout in seconds
        self.last_timeout = time.time()
        
        # Load node key pair
        self._load_keys()

    def _load_keys(self):
        """Load node key pair"""
        try:
            # Load private key from file
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            if not os.path.exists(private_key_path):
                self.logger.warning(f"Private key file not found: {private_key_path}")
                # Generate new key pair
                self._generate_keys()
                return
                
            with open(private_key_path, 'rb') as f:
                self.private_key = ECC.import_key(f.read())
                
            # Load public key from file
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            if not os.path.exists(public_key_path):
                self.logger.warning(f"Public key file not found: {public_key_path}")
                # Generate new key pair
                self._generate_keys()
                return
                
            with open(public_key_path, 'rb') as f:
                self.public_key = ECC.import_key(f.read())
                
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            # Generate new key pair
            self._generate_keys()
            
    def _generate_keys(self):
        """Generate new ECC key pair"""
        try:
            # Generate 256-bit ECC key pair
            key = ECC.generate(curve='P-256')
            self.private_key = key
            self.public_key = key.public_key()
            
            # Ensure pki_files directory exists
            if not os.path.exists('pki_files'):
                os.makedirs('pki_files')
            
            # Save private key
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.export_key(format='PEM'))
            
            # Save public key
            public_key_path = os.path.join('pki_files', f'node{self.node_id}_public.pem')
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.export_key(format='PEM'))
                
            self.logger.info(f"Generated new key pair for node {self.node_id}")
        except Exception as e:
            self.logger.error(f"Failed to generate keys: {e}")
            raise

    def prepare(self, value: Any, sequence: Optional[int] = None) -> BFTMessage:
        """Prepare phase"""
        if sequence is None:
            sequence = self.sequence
        self.proposed_value = value
        self.phase = BFTPhase.PREPARE
        self.sequence = sequence
        
        # Create prepare message
        prepare_msg = BFTMessage(
            type='prepare',
            value=value,
            phase=BFTPhase.PREPARE,
            node_id=self.node_id,
            view=self.view,
            sequence=sequence,
            timestamp=time.time()
        )
        
        # Sign message
        prepare_msg.signature = self._sign_message(prepare_msg)
        return prepare_msg

    def precommit(self, prepare_msg: BFTMessage) -> Optional[BFTMessage]:
        """Pre-commit phase"""
        if not self._verify_message(prepare_msg):
            return None
            
        if self._verify_prepare(prepare_msg):
            self.phase = BFTPhase.PRECOMMIT
            
            # Create pre-commit message
            precommit_msg = BFTMessage(
                type='precommit',
                value=prepare_msg.value,
                phase=BFTPhase.PRECOMMIT,
                node_id=self.node_id,
                view=self.view,
                sequence=prepare_msg.sequence
            )
            
            # Sign message
            precommit_msg.signature = self._sign_message(precommit_msg)
            return precommit_msg
        return None

    def commit(self, precommit_msg: BFTMessage) -> Optional[BFTMessage]:
        """Commit phase"""
        if not self._verify_message(precommit_msg):
            return None
            
        if self._verify_precommit(precommit_msg):
            self.phase = BFTPhase.COMMIT
            
            # Create commit message
            commit_msg = BFTMessage(
                type='commit',
                value=precommit_msg.value,
                phase=BFTPhase.COMMIT,
                node_id=self.node_id,
                view=self.view,
                sequence=precommit_msg.sequence
            )
            
            # Sign message
            commit_msg.signature = self._sign_message(commit_msg)
            return commit_msg
        return None

    def _verify_prepare(self, msg: BFTMessage) -> bool:
        """Verify prepare message"""
        if msg.sequence not in self.prepared_values:
            self.prepared_values[msg.sequence] = set()
            
        self.prepared_values[msg.sequence].add(msg.value)
        prepare_messages = [m for m in self.messages.get('prepare', []) 
                          if m.sequence == msg.sequence]
        
        # Check if enough prepare messages received
        if len(prepare_messages) < (self.total_nodes - self.f):
            return False
            
        # Check if all prepare messages have consistent values
        values = {m.value for m in prepare_messages}
        if len(values) > 1:
            self.logger.warning(f"Conflicting values in prepare messages: {values}")
            return False
            
        return True

    def _verify_precommit(self, msg: BFTMessage) -> bool:
        """Verify pre-commit message"""
        if msg.sequence not in self.committed_values:
            self.committed_values[msg.sequence] = set()
            
        self.committed_values[msg.sequence].add(msg.value)
        precommit_messages = [m for m in self.messages.get('precommit', []) 
                            if m.sequence == msg.sequence]
        
        # Check if enough pre-commit messages received
        if len(precommit_messages) < (self.total_nodes - self.f):
            return False
            
        # Check if all pre-commit messages have consistent values
        values = {m.value for m in precommit_messages}
        if len(values) > 1:
            self.logger.warning(f"Conflicting values in precommit messages: {values}")
            return False
            
        return True

    def handle_message(self, msg: BFTMessage) -> Optional[BFTMessage]:
        """Handle received message"""
        # Verify message
        if not self._verify_message(msg):
            self.logger.warning(f"Invalid message received from node {msg.node_id}")
            return None
            
        # Store message
        if msg.type not in self.messages:
            self.messages[msg.type] = []
        self.messages[msg.type].append(msg)

        # Process based on message type
        if msg.type == 'prepare':
            return self.precommit(msg)
        elif msg.type == 'precommit':
            return self.commit(msg)
        elif msg.type == 'commit':
            if self._check_consensus(msg.sequence):
                self.decided_value = msg.value
                self.logger.info(f"Consensus reached for sequence {msg.sequence}")
                return None
        return None

    def _verify_message(self, msg: BFTMessage) -> bool:
        """Verify message validity"""
        # Check view number
        if msg.view < self.view:
            self.logger.warning(f"Message view {msg.view} is less than current view {self.view}")
            return False
            
        # Check sequence number
        if msg.sequence < self.sequence:
            self.logger.warning(f"Message sequence {msg.sequence} is less than current sequence {self.sequence}")
            return False
            
        # Check signature
        if not msg.signature:
            self.logger.warning("Message has no signature")
            return False
            
        # Verify signature
        try:
            # Use ECC public key to verify signature
            return self._verify_signature(msg, self.public_key)
        except Exception as e:
            self.logger.error(f"Failed to verify message: {e}")
            return False

    def _sign_message(self, msg: BFTMessage) -> str:
        """Sign message"""
        # Serialize message content
        msg_data = {
            'type': msg.type,
            'value': msg.value,
            'phase': msg.phase.value,
            'node_id': msg.node_id,
            'view': msg.view,
            'sequence': msg.sequence,
            'timestamp': msg.timestamp
        }
        serialized_data = dill.dumps(msg_data)
        
        # Calculate message hash
        hash_obj = SHA256.new(serialized_data)
        
        # Use ECC private key to sign
        signer = DSS.new(self.private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        
        return signature.hex()

    def _verify_signature(self, msg: BFTMessage, public_key: ECC.EccKey) -> bool:
        """Verify message signature"""
        try:
            # Serialize message content
            msg_data = {
                'type': msg.type,
                'value': msg.value,
                'phase': msg.phase.value,
                'node_id': msg.node_id,
                'view': msg.view,
                'sequence': msg.sequence,
                'timestamp': msg.timestamp
            }
            serialized_data = dill.dumps(msg_data)
            
            # Calculate message hash
            hash_obj = SHA256.new(serialized_data)
            
            # Use ECC public key to verify signature
            verifier = DSS.new(public_key, 'fips-186-3')
            verifier.verify(hash_obj, bytes.fromhex(msg.signature))
            return True
        except Exception as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False

    def _check_consensus(self, sequence: int) -> bool:
        """Check if consensus is reached"""
        if sequence not in self.committed_values:
            return False
            
        values = self.committed_values[sequence]
        if len(values) > 1:
            self.logger.warning(f"Multiple values in consensus: {values}")
            return False
            
        return len(values) >= (self.total_nodes - self.f)

    def check_timeout(self) -> bool:
        """Check if timeout occurred"""
        return time.time() - self.last_timeout > self.timeout

    def reset_timeout(self):
        """Reset timeout timer"""
        self.last_timeout = time.time()

    def start_view_change(self):
        """Start view change"""
        self.view += 1
        self.sequence = 0
        self.messages.clear()
        self.votes.clear()
        self.prepared_values.clear()
        self.committed_values.clear()
        self.reset_timeout()
        self.logger.info(f"Starting view change to view {self.view}") 