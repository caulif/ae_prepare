import time
import logging
import re
import dill
from typing import List, Dict

import pandas as pd
import numpy as np
import sympy
import random
import os

from agent.Agent import Agent
from .HPRF.hprf import load_initialization_values, HPRF
from message.Message import Message
from util import param, util
from util.crypto.secretsharing.vss import VSS
from agent.Aion.bft import BFTProtocol, BFTMessage
from agent.Aion.bft_view import ViewChangeProtocol, CheckpointProtocol
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import ECC

class SA_AggregatorAgent(Agent):
    """
    Represents a server agent participating in a secure aggregation protocol.
    """

    def __str__(self):
        return "[server]"

    def __init__(self, id, name, type,
                 random_state=None,
                 msg_fwd_delay=1_000_000,  # Delay for forwarding peer-to-peer client messages (in nanoseconds)
                 round_time=pd.Timedelta("10s"),
                 iterations=4,
                 key_length=32,
                 num_clients=10,
                 parallel_mode=1,
                 debug_mode=0,
                 vector_len=10_000,
                 aggregator_size=8,
                 users=None):
        """
        Initializes the server agent.

        Args:
            id (int): Agent ID.
            name (str): Agent name.
            type (str): Agent type.
            random_state (numpy.random.RandomState): Random number generator.
            msg_fwd_delay (int): Time for forwarding peer-to-peer client messages.
            round_time (pandas.Timedelta): Waiting time per round.
            iterations (int): Number of iterations.
            key_length (int): Key length.
            num_clients (int): Number of users for each training round.
            parallel_mode (int): Parallel mode.
            debug_mode (int): Debug mode.
            vector_len (int): Vector length.
            aggregator_size (int): Aggregator size.
            users (set): Set of user IDs.
        """
        super().__init__(id, name, type, random_state)

        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig(level=logging.DEBUG)

        # System parameters
        self.msg_fwd_delay = msg_fwd_delay
        self.round_time = round_time
        self.no_of_iterations = iterations
        self.parallel_mode = parallel_mode

        # Input parameters
        self.num_clients = num_clients
        self.users = users if users is not None else set()
        self.vector_len = vector_len
        self.vector_dtype = param.vector_type

        # Security parameters
        self.aggregator_size = aggregator_size
        self.committee_threshold = 0
        self.prime = param.prime

        # Initialize VSS
        self.vss = VSS(self.prime)

        # Data storage
        self.times = []
        self.client_id_list = None
        self.seed_sum_hprf = None
        self.selected_indices = None
        self.committee_shares_sum = {}
        self.seed_sum = None
        self.recv_user_masked_vectors = {}
        self.recv_committee_shares_sum = {}
        self.user_masked_vectors = {}
        self.user_committee = {}
        self.committee_sigs = {}
        self.recv_committee_sigs = {}
        self.receive_mask = {}
        self.mask_commitments = {}  # Store commitments for verification
        self.recv_shared_masks = {}  # Store received shared masks

        # Initialize vectors
        self.vec_sum_partial = np.zeros(self.vector_len, dtype=object)
        self.final_sum = np.zeros(self.vector_len, dtype=object)

        # Track current protocol iteration and round
        self.current_iteration = 1
        self.current_round = 0

        # Parameters for poison defense module
        self.l2_old = []
        self.linf_old = 0.1
        self.linf_HPRF_old = 0.05
        self.b_old = 0.2

        self.hprf_prime = 0
        # Accumulated time
        self.elapsed_time = {
            'REPORT': pd.Timedelta(0),
            'CROSSCHECK': pd.Timedelta(0),
            'RECONSTRUCTION': pd.Timedelta(0),
        }

        # Message processing map
        self.aggProcessingMap = {
            0: self.initialize,
            1: self.report,
            2: self.forward_signatures,
            3: self.reconstruction,
        }

        # Round name map
        self.namedict = {
            0: "initialize",
            1: "report",
            2: "forward_signatures",
            3: "reconstruction",
        }

        # Record time for each part
        self.timings = {
            "Seed sharing": [],
            "Legal clients confirmation": [],
            # "Masked model generation": [],
            "Online clients confirmation": [],
            "Aggregate share reconstruction": [],
            "Model aggregation": [],
        }
        self._seed_sharing_verify_time = 0
        self._seed_sharing_verified_count = 0

        # 初始化BFT协议
        self.bft_protocol = BFTProtocol(
            node_id=self.id,
            total_nodes=self.num_clients,
            f=self.num_clients // 3
        )
        
        # BFT相关状态
        self.bft_messages = {}
        self.bft_responses = {}
        self.bft_consensus = {}

        # 初始化视图切换和检查点协议
        self.view_protocol = ViewChangeProtocol(
            node_id=self.id,
            total_nodes=self.num_clients
        )
        self.checkpoint_protocol = CheckpointProtocol(node_id=self.id)
        
        # 视图切换相关状态
        self.view_change_messages = {}
        self.view_change_timeout = 5  # 秒

    # Simulate lifecycle message
    def kernelStarting(self, startTime):
        """
        Initializes the server state when the kernel starts.

        Args:
            startTime (pandas.Timestamp): Kernel start time.
        """
        self.starttime = time.time()
        self.setComputationDelay(0)
        self.kernel.custom_state['Legal clients confirmation'] = 0
        self.kernel.custom_state['Online clients confirmation'] = 0
        self.kernel.custom_state['Aggregate share reconstruction'] = 0
        self.kernel.custom_state['Model aggregation'] = 0
        
        # 动态导入 ClientAgent 以避免循环导入
        from agent.Aion.SA_ClientAgent import SA_ClientAgent as ClientAgent
        self.ClientAgent = ClientAgent
        
        super().kernelStarting(startTime)

    def kernelStopping(self):
        """Execute cleanup work when kernel stops, including calculating average time"""
        # Calculate average time and record to kernel state
        for part, times in self.timings.items():
            if times:  # Ensure list is not empty
                avg_time = sum(times) / len(times)
                self.kernel.custom_state[part] = avg_time
            else:
                self.kernel.custom_state[part] = 0  # If list is empty, set to 0

        super().kernelStopping()

    def wakeup(self, currentTime):
        """
        Called at the end of each round, performs processing according to the current round.

        Args:
            currentTime (pandas.Timestamp): Current simulation time.
        """
        super().wakeup(currentTime)
        self.agent_print(
            f"wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")
        self.aggProcessingMap[self.current_round](currentTime)

    def receiveMessage(self, currentTime, msg):
        """
        Receives and stores messages.

        Args:
            currentTime (pandas.Timestamp): Current time.
            msg (Message): Received message.
        """
        super().receiveMessage(currentTime, msg)
        sender_id = msg.body['sender']

        if msg.body["msg"] == "VECTOR" and msg.body['iteration'] == self.current_iteration:
            self.recv_user_masked_vectors[sender_id] = msg.body['masked_vector']

        elif msg.body["msg"] == "SIGN" and msg.body['iteration'] == self.current_iteration:
            self.recv_committee_sigs[sender_id] = msg.body['signed_labels']

        elif msg.body["msg"] == "hprf_SUM_SHARES" and msg.body['iteration'] == self.current_iteration:
            self.recv_committee_shares_sum[sender_id] = msg.body['sum_shares']

        elif msg.body["msg"] == "BFT_SIGN":
            # 处理BFT消息
            bft_msg = msg.body['bft_message']
            self.bft_messages[msg.body['sender']] = bft_msg
            
            # 处理消息并可能产生响应
            response = self.bft_protocol.handle_message(bft_msg)
            if response:
                self.bft_responses[msg.body['sender']] = response
                
        elif msg.body["msg"] == "BFT_RESPONSE":
            # 处理BFT响应
            bft_msg = msg.body['bft_message']
            self.bft_responses[msg.body['sender']] = bft_msg
            
            # 检查是否达成共识
            if self._check_consensus():
                self._handle_consensus()
                
        elif msg.body["msg"] == "SHARED_MASK":
            self.handle_shared_mask(currentTime, msg)
            
        elif msg.body["msg"] == "MASK_COMMITMENTS":
            self.handle_mask_commitments(currentTime, msg)
            
        elif msg.body['msg'] == "VIEW_CHANGE":
            self.handle_view_change(currentTime, msg)
            
        else:
            self.agent_print(f"Unknown message type: {msg.body['msg']}")

    def initialize(self, currentTime):
        """Initialization phase, including committee member selection and client validation"""
        start_time = time.time()
        dt_protocol_start = pd.Timestamp('now')
        
        # Select committee members
        self.user_committee = param.choose_committee(param.root_seed, self.aggregator_size, self.num_clients)
        # Use 1/3 of committee size as threshold
        self.committee_threshold = max(2, len(self.user_committee) // 3)

        # Initialize BFT protocol
        self.bft_protocol = BFTProtocol(
            node_id=self.id,
            total_nodes=self.num_clients,
            f=self.num_clients // 3
        )

        # Validate client validity
        valid_clients = self._validate_clients()
        
        # Use BFT to reach consensus on valid client set
        valid_clients_message = Message({
            "msg": "VALID_CLIENTS",
            "iteration": 0,
            "valid_clients": valid_clients
        })
        self.timings["Legal clients confirmation"].append(time.time() - start_time)
        # Broadcast valid client set
        self._bft_broadcast_with_consensus(valid_clients_message, self.user_committee)
        # Record Legal clients confirmation time

        # Send initial model
        initial_model_weights = np.ones(self.vector_len, dtype=self.vector_dtype) * 1000
        model_message = Message({
            "msg": "INITIAL_MODEL",
            "iteration": 0,
            "model_weights": initial_model_weights
        })
        
        self.client_id_list = valid_clients
        self._bft_broadcast_with_consensus(model_message, self.client_id_list)

        self.current_round = 1
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.setWakeup(currentTime + server_comp_delay + pd.Timedelta('2s'))

    def _validate_clients(self) -> List[int]:
        """Validate client validity"""
        valid_clients = []
        for client_id in range(self.num_clients):
            if self._verify_client_credentials(client_id):
                valid_clients.append(client_id)
        return valid_clients

    def _verify_client_credentials(self, client_id: int) -> bool:
        """Verify client credentials"""
        # In actual implementation, this should verify client certificates and signatures
        # Here using a simple example implementation
        return True

    def _bft_broadcast_with_consensus(self, message: Message, recipients: List[int]) -> Dict[int, BFTMessage]:
        """Broadcast using BFT protocol and wait for consensus"""
        # Preparation phase - only count local computation time
        compute_start = time.time()
        prepare_msg = self.bft_protocol.prepare(message)
        compute_time = time.time() - compute_start

        # Determine BFT message type based on message type
        bft_msg_type = "BFT_SIGN_LEGAL"
        if message.body['msg'] == "ONLINE_CLIENTS":
            bft_msg_type = "BFT_SIGN_ONLINE"
        elif message.body['msg'] == "FINAL_SUM":
            bft_msg_type = "BFT_SIGN_FINAL"

        # Send to all recipients
        for recipient_id in recipients:
            self.sendMessage(
                recipient_id,
                Message({
                    "msg": bft_msg_type,
                    "iteration": self.current_iteration,
                    "sender": self.id,
                    "bft_message": prepare_msg,
                    "sign_message": message
                }),
                tag="comm_dec_server"
            )

        # Wait for consensus
        start_time = time.time()
        Delta = pd.Timedelta('0.005s')
        responses = {}
        
        while time.time() - start_time < 2 * Delta.total_seconds():
            if len(responses) >= (len(recipients) - self.bft_protocol.f):
                # Check if consensus is reached - only count local computation time
                check_start = time.time()
                if self._check_bft_consensus(responses):
                    compute_time += time.time() - check_start
                    break
            time.sleep(0.0001)
        
        return responses, compute_time

    def _check_bft_consensus(self, responses: Dict[int, BFTMessage]) -> bool:
        """Check if BFT consensus is reached"""
        if len(responses) < (self.num_clients - self.bft_protocol.f):
            return False
        
        # Check if all responses are consistent
        values = [msg.value for msg in responses.values()]
        return all(v == values[0] for v in values)

    def report(self, currentTime):
        """Process client reports, including online client confirmation"""
        # Only count local computation time
        compute_start = time.time()

        self.report_read_from_pool()
        self.report_process()
        self.report_clear_pool()
        compute_time = time.time() - compute_start

        # BFT confirm online client information
        online_clients_list = [1 if i in self.recv_user_masked_vectors else 0 for i in range(self.num_clients)]
        online_clients_list_bytes = bytes(online_clients_list)
        message_online_clients = Message({
            "msg": "ONLINE_CLIENTS",
            "iteration": self.current_iteration,
            "online_clients": online_clients_list_bytes
        })
        
        # Use BFT to reach consensus on online client set
        bft_start_time = time.time()
        _, consensus_time = self._bft_broadcast_with_consensus(message_online_clients, self.user_committee)
        bft_time = time.time() - bft_start_time

        # Record online client confirmation time
        self.timings["Online clients confirmation"].append(bft_time)

        self.current_round = 2
        # Use actual computation time to determine next wakeup time
        server_comp_delay = pd.Timedelta(seconds=compute_time + bft_time)
        self.setWakeup(currentTime + server_comp_delay)

    def report_read_from_pool(self):
        """Reads data from the receiving pool."""
        self.user_masked_vectors = self.recv_user_masked_vectors
        self.recv_user_masked_vectors = {}

    def report_clear_pool(self):
        """Clears the message pool."""
        self.recv_committee_shares_sum = {}
        self.recv_committee_sigs = {}

    def report_process(self):
        """
        Processes masked vectors and calculates the partial sum.
        """
        self.agent_print("Number of collected vectors:", len(self.user_masked_vectors))

        self.client_id_list = list(self.user_masked_vectors.keys())

        self.selected_indices, self.b_old = self.MMF(self.user_masked_vectors, self.l2_old, self.linf_old,
                                                     self.linf_HPRF_old, self.b_old,
                                                     self.current_iteration)
        initialization_values_filename = os.path.join("agent", "Aion", "HPRF", "initialization_values")
        n, m, p, q = load_initialization_values(initialization_values_filename)
        self.hprf_prime = p

        self.vec_sum_partial = np.zeros(self.vector_len, dtype=object)
        for id in self.selected_indices:
            if len(self.user_masked_vectors[id]) != self.vector_len:
                raise RuntimeError("Client sent a vector with an incorrect length.")
            self.vec_sum_partial += self.user_masked_vectors[id] 
            self.vec_sum_partial %= self.hprf_prime


    def forward_signatures(self, currentTime):
        """
        Forwards signatures and requests secret shares.

        Args:
            currentTime (pandas.Timestamp): Current simulation time.
        """
        dt_protocol_start = pd.Timestamp('now')
        self.check_time = time.time()

        for id in self.user_committee:
            self.sendMessage(id,
                             Message({"msg": "request shares sum",
                                      "iteration": self.current_iteration,
                                      "request id list": self.selected_indices,
                                      }),
                             tag="comm_sign_server")

        self.current_round = 3
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.agent_print("Crosscheck step running time:", server_comp_delay)
        self.setWakeup(currentTime + server_comp_delay + param.wt_Aion_reconstruction)

        self.recordTime(dt_protocol_start, "CROSSCHECK")
        self.check_time = time.time() - self.check_time

    def reconstruction(self, currentTime):
        """
        Performs vector reconstruction and sends the final result to clients.

        Args:
            currentTime (pandas.Timestamp): Current simulation time.
        """
        dt_protocol_start = pd.Timestamp('now')
        self.reco_time = time.time()

        self.reconstruction_read_from_pool()
        self.reconstruction_process()
        self.reconstruction_clear_pool()
        self.reconstruction_send_message()

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.agent_print("Reconstruction time:", server_comp_delay)
        self.recordTime(dt_protocol_start, "RECONSTRUCTION")
        self.reco_time = time.time() - self.reco_time

        print()
        print("######## Iteration completed ########")
        print(f"[Server] Completed iteration {self.current_iteration} at {currentTime + server_comp_delay}")
        print()

        self.current_round = 1
        self.current_iteration += 1
        if self.current_iteration > self.no_of_iterations:
            return

        self.setWakeup(currentTime + server_comp_delay + param.wt_Aion_report)

    def reconstruction_read_from_pool(self):
        """Reads decryption shares from the receiving pool."""
        while len(self.recv_committee_shares_sum) < self.committee_threshold:
            time.sleep(0.01)

        self.committee_shares_sum = self.recv_committee_shares_sum
        self.recv_committee_shares_sum = {}

    def reconstruction_clear_pool(self):
        """Clears all message pools."""
        self.user_masked_vectors = {}
        self.committee_shares_sum = {}

        self.recv_user_masked_vectors = {}
        self.recv_committee_shares_sum = {}
        self.recv_user_masked_vectors = {}

    def reconstruction_process(self):
        """Process reconstruction phase"""
        self.agent_print("Number of collected shares:", len(self.committee_shares_sum))
        if len(self.committee_shares_sum) < self.committee_threshold:
            raise RuntimeError("Not enough decryption shares received.")

        # Only count local computation time
        compute_start = time.time()
        
        # 1. Recover seed sum from committee members' combined shares
        committee_shares = list(self.committee_shares_sum.values())
        self.seed_sum = self.vss.reconstruct(committee_shares, self.prime)

        
        # 2. Generate mask vector using recovered seed
        initialization_values_filename = os.path.join("agent", "Aion", "HPRF", "initialization_values")
        n, m, p, q = load_initialization_values(initialization_values_filename)
        filename = os.path.join("agent", "Aion", "HPRF", "matrix")
        hprf = HPRF(n, m, p, q, filename)
        self.seed_sum_hprf = hprf.hprf(self.seed_sum, self.current_iteration, self.vector_len)
        self.final_sum = self.vec_sum_partial - self.seed_sum_hprf
        self.final_sum %= self.hprf_prime
        self.final_sum //= len(self.selected_indices)
        self.final_sum = np.array(self.final_sum, dtype=object)
        self.l2_old = [np.linalg.norm(self.final_sum)] + self.l2_old[:1]
        self.linf_old = np.max(np.abs(self.final_sum))
        self.linf_HPRF_old = np.max(np.abs(self.seed_sum_hprf))
        compute_time = time.time() - compute_start
        self.timings["Aggregate share reconstruction"].append(compute_time)
        
        start_time = time.time()
        # Create global model message
        message_final_sum = Message({
            "msg": "FINAL_SUM",
            "iteration": self.current_iteration,
            "final_sum": self.final_sum
        })

        # Use BFT to reach consensus on global model
        _, consensus_time = self._bft_broadcast_with_consensus(message_final_sum, self.user_committee)
        self.timings["Model aggregation"].append(time.time()-start_time)

    def reconstruction_send_message(self):
        """Sends the final result to clients."""
        for id in self.users:
            self.sendMessage(id,
                             Message({"msg": "REQ", "sender": 0, "output": 1}),
                             tag="comm_output_server")

    def MMF(self, masked_updates, l2_old, linf_old, linf_HPRF_old, b_old, current_round):
        """
        Function to select benign clients.

        Args:
            masked_updates (dict): Dictionary of masked updates from clients, where the key is the client index (int) and value is a 1D numpy array.
            ... (other parameters remain unchanged)

        Returns:
            list: List of benign client indices.
            float: Threshold b for the current round.
        """
        WEIGHT = 1.0  # Weight
        MIN_THRESHOLD = 0.3  # Minimum threshold
        RESUME = False
        RESUMED_NAME = None

        cnt = len(masked_updates)

        # Calculate L2 norm and sort, keep original index
        l2_norm = {k: np.linalg.norm(v) for k, v in masked_updates.items()}
        sorted_l2_norm = dict(sorted(l2_norm.items(), key=lambda item: item[1]))

         # Dynamically adjust threshold b
        if current_round <= 3 or (
                RESUME and current_round <= int(
                    re.findall(r'\d+\d*', RESUMED_NAME.split('/')[1])[0]) + 3 if RESUMED_NAME else 0):
            b = list(sorted_l2_norm.values())[int(MIN_THRESHOLD * cnt)]
        else:
            b = (l2_old[1] + linf_HPRF_old) / (l2_old[0] + linf_HPRF_old) * b_old

        # Select benign clients using the sorted dictionary
        selected_indices = []
        count = 0
        for k, v in sorted_l2_norm.items():
            if v <= b:
                selected_indices.append(k)
                count += 1
            if count >= int(0.8 * cnt):  # Limit maximum number here
                break

        benign_index = max(int(MIN_THRESHOLD * cnt),
                           min(int(0.8 * cnt), len(selected_indices)))
        if len(selected_indices) > benign_index:
            selected_indices = selected_indices[:benign_index]
        else:
            selected_indices = list(sorted_l2_norm.keys())[:benign_index]
        return selected_indices, b

    def vss_verify_share(self, share, commitments, prime=None):
        """
        Verify a share against the commitments.
        
        Args:
            share: A share in the format (share_index, share_value).
            commitments: List of commitments.
            prime: The prime number to use.
            
        Returns:
            is_valid: True if the share is valid, False otherwise.
        """
        if prime is None:
            prime = self.prime
            
        return self.vss.verify_share(share, commitments, prime)
        
    def vss_reconstruct(self, shares, prime=None):
        """
        Reconstruct the secret from shares.
        
        Args:
            shares: List of shares in the format [(share_index, share_value)].
            prime: The prime number to use.
            
        Returns:
            secret: The reconstructed secret.
        """
        if prime is None:
            prime = self.prime
            
        return self.vss.reconstruct(shares, prime)

    # ======================== UTIL ========================
    def recordTime(self, startTime, categoryName):
        """
        Records the elapsed time.

        Args:
            startTime (pandas.Timestamp): Start time.
            categoryName (str): Category name.
        """
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime

    def agent_print(*args, **kwargs):
        """
        Custom print function that adds a [Server] header before printing.
        """
        print(f"[Server] ", *args, **kwargs)

    def handle_shared_mask(self, currentTime, msg):
        """
        Handles a shared mask message.
        """
        sender_id = msg.body["sender"]
        shared_mask = msg.body["shared_mask"]
        commitments = msg.body.get("commitments", None)
        
        # 存储份额和承诺
        self.recv_shared_masks[sender_id] = shared_mask
        if commitments is not None:
            self.mask_commitments[sender_id] = commitments
            
        # 检查是否收到足够的份额
        if len(self.recv_shared_masks) >= self.committee_threshold:
            # 将收到的所有份额相加
            combined_share = None
            for share in self.recv_shared_masks.values():
                if combined_share is None:
                    combined_share = share
                else:
                    # 将对应位置的值相加，保持索引和盲化值
                    combined_share = (
                        combined_share[0],  # 保持索引不变
                        (combined_share[1] + share[1]) % self.prime,  # 份额值相加
                        (combined_share[2] + share[2]) % self.prime   # 盲化值相加
                    )
            
            # 发送相加后的份额给服务器
            self.sendMessage(self.AggregatorAgentID,
                          Message({"msg": "hprf_SUM_SHARES",
                                   "iteration": self.current_iteration,
                                   "sender": self.id,
                                   "sum_shares": combined_share,  # 直接发送完整的份额元组
                                   }),
                          tag="comm_secret_sharing")
            
            self.agent_print(f"Committee member {self.id} sent combined share to server")
            
            # 清空接收到的份额
            self.recv_shared_masks = {}
            self.mask_commitments = {}

    def handle_mask_commitments(self, currentTime, msg):
        """
        Handles mask commitments message.

        Args:
            currentTime (pandas.Timestamp): The current simulation time.
            msg (Message): The message containing the mask commitments.
        """
        sender_id = msg.body["sender"]
        commitments = msg.body["commitments"]
        
        # Store the commitments for verification
        self.mask_commitments[sender_id] = commitments
        self.agent_print(f"Received mask commitments from client {sender_id}")
        
        # 检查是否已经选择了客户端
        if self.selected_indices is None:
            return
            
        # Check if we have received all commitments
        if len(self.mask_commitments) == len(self.selected_indices):
            self.agent_print("Received all mask commitments")
            
    def verify_all_shares(self):
        """
        Verifies all shares against their commitments.
        
        Returns:
            is_valid: True if all shares are valid, False otherwise.
        """
        for client_id, shares in self.recv_shared_masks.items():
            if client_id in self.mask_commitments:
                commitments = self.mask_commitments[client_id]
                is_valid = self.vss_verify_share(shares, commitments, self.prime)
                if not is_valid:
                    self.agent_print(f"Invalid share from client {client_id}")
                    return False
        return True

    def crosscheck(self, currentTime):
        """
        Performs crosscheck and requests shares from committee members.

        Args:
            currentTime (pandas.Timestamp): Current simulation time.
        """
        dt_protocol_start = pd.Timestamp('now')
        self.check_time = time.time()
        
        # Verify all shares
        # if not self.verify_all_shares():
        #     self.agent_print("Some shares are invalid, aborting crosscheck")
        #     return

        for id in self.user_committee:
            self.sendMessage(id,
                             Message({"msg": "request shares sum",
                                      "iteration": self.current_iteration,
                                      "request id list": self.selected_indices,
                                      }),
                             tag="comm_sign_server")

        self.current_round = 3
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.agent_print("Crosscheck step running time:", server_comp_delay)
        self.setWakeup(currentTime + server_comp_delay + param.wt_Aion_reconstruction)

        self.recordTime(dt_protocol_start, "CROSSCHECK")
        self.check_time = time.time() - self.check_time

    def _check_consensus(self):
        """Check if consensus is reached"""
        if len(self.bft_responses) < (self.num_clients - self.bft_protocol.f):
            return False
            
        # Check if all responses are consistent
        values = [msg.value for msg in self.bft_responses.values()]
        return all(v == values[0] for v in values)

    def _handle_consensus(self):
        """Handle consensus result"""
        if self._check_consensus():
            # Get consensus value
            consensus_value = next(iter(self.bft_responses.values())).value
            self.bft_consensus[self.current_iteration] = consensus_value
            
            # Execute post-consensus actions
            self._execute_consensus_action(consensus_value)

    def _execute_consensus_action(self, value):
        """Execute post-consensus actions"""
        # Implement based on specific requirements
        pass

    def handle_view_change(self, currentTime, msg):
        """Handle view change message"""
        if msg.body['msg'] == "VIEW_CHANGE":
            view_change_msg = msg.body['view_change_message']
            if self.view_protocol.handle_view_change(view_change_msg):
                # View change consensus reached
                self._complete_view_change(view_change_msg)
                
    def _complete_view_change(self, view_change_msg):
        """Complete view change"""
        # Update view
        self.view_protocol.current_view = view_change_msg.view
        
        # Restore state
        self._restore_state_from_checkpoint(view_change_msg.last_checkpoint)
        
        # Re-broadcast unfinished messages
        self._rebroadcast_prepared_messages(view_change_msg.prepared_messages)
        
    def _restore_state_from_checkpoint(self, checkpoint_number):
        """Restore state from checkpoint"""
        if checkpoint_number in self.checkpoint_protocol.stable_checkpoints:
            checkpoint = self.checkpoint_protocol.stable_checkpoints[checkpoint_number]
            # Restore state
            self._apply_checkpoint_state(checkpoint['state'])
            
    def _apply_checkpoint_state(self, state):
        """Apply checkpoint state"""
        # Implement state restoration logic
        pass
        
    def _rebroadcast_prepared_messages(self, prepared_messages):
        """Re-broadcast prepared messages"""
        for msg in prepared_messages:
            self._bft_broadcast_with_consensus(msg, self.client_id_list)
            
    def create_checkpoint(self):
        """Create checkpoint"""
        state = {
            'current_iteration': self.current_iteration,
            'bft_messages': self.bft_messages,
            'bft_responses': self.bft_responses,
            'bft_consensus': self.bft_consensus
        }
        return self.checkpoint_protocol.create_checkpoint(state)
        
    def verify_checkpoint(self, checkpoint):
        """Verify checkpoint"""
        return self.checkpoint_protocol.verify_checkpoint(checkpoint)
        
    def stabilize_checkpoint(self, checkpoint_number):
        """Stabilize checkpoint"""
        self.checkpoint_protocol.stabilize_checkpoint(checkpoint_number)

    def _load_keys(self):
        """Load node keys"""
        try:
            # Load private key
            private_key_path = os.path.join('pki_files', f'node{self.node_id}.pem')
            if not os.path.exists(private_key_path):
                self.logger.warning(f"Private key file not found: {private_key_path}")
                # Generate new key pair
                self._generate_keys()
                return
                
            with open(private_key_path, 'rb') as f:
                self.private_key = ECC.import_key(f.read())
                
            # Load public key
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