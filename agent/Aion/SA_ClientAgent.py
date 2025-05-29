import torch

from agent.Agent import Agent
from agent.HPRF.hprf import load_initialization_values, SHPRG
from message.Message import Message
import dill
import time
import logging
import pandas as pd
import random
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import ECC

from util import param
from util import util
from util.crypto.secretsharing.vss import VSS

from agent.Aion.tool import *
from agent.Aion.bft import BFTProtocol, BFTMessage
import gmpy2

class SA_ClientAgent(Agent):
    """Represents a client agent participating in a secure aggregation protocol."""

    def __str__(self):
        return "[client]"

    def __init__(self, id, name, type,
                 iterations=4,
                 key_length=32,
                 num_clients=128,
                 neighborhood_size=1,
                 debug_mode=0,
                 Dimension=10000,
                 commit_size=8,
                 msg_name=None,
                 random_state=None):
        """
        Initializes the client agent.

        Args:
            id (int): Unique ID of the agent.
            name (str): Name of the agent.
            type (str): Type of the agent.
            iterations (int, optional): Number of iterations for the protocol. Defaults to 4.
            key_length (int, optional): Length of the encryption key in bytes. Defaults to 32.
            num_clients (int, optional): Number of clients participating in the protocol. Defaults to 128.
            neighborhood_size (int, optional): Number of neighbors for each client. Defaults to 1.
            debug_mode (int, optional): Whether to enable debug mode. Defaults to 0.
            random_state (random.Random, optional): Random number generator. Defaults to None.
        """

        super().__init__(id, name, type, random_state)

        self.commit_size = commit_size
        self.msg_name = msg_name
        self.report_time = None
        self.reco_time = None
        self.check_time = None
        self.cipher_stored = None
        self.key_length = None
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig()

        self.key = util.read_key(f"pki_files/client{self.id}.pem")

        self.num_clients = num_clients
        self.neighborhood_size = neighborhood_size
        self.vector_len = Dimension
        self.vector_dtype = param.vector_type

        self.key_length = key_length

        self.user_committee = param.choose_committee(param.root_seed,
                                                     self.commit_size,
                                                     self.num_clients)

        self.committee_shared_sk = None
        self.committee_member_idx = None

        self.prime = param.prime
        
        # Initialize VSS with the correct prime
        self.vss = VSS(prime=self.prime)

        self.elapsed_time = {'REPORT': pd.Timedelta(0),
                             'CROSSCHECK': pd.Timedelta(0),
                             'RECONSTRUCTION': pd.Timedelta(0),
                             }

        self.initial_time = 0
        self.ag_time = 0

        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.current_base = 0

        self.setup_complete = False
        self.mask_seeds = []
        self.receive_mask_shares = {}
        self.mask_commitments = {}
        self.flag = 0
        # 初始化BFT协议
        self.bft_protocol = BFTProtocol(
            node_id=self.id,
            total_nodes=self.num_clients,
            f=self.num_clients // 3  # 假设最多容忍1/3的拜占庭节点
        )
        self.shared_mask_count = 0

        # 统计各阶段时间
        self.timings = {
            "Seed sharing": [],
            "REPORT": [],
            "CROSSCHECK": [],
            "RECONSTRUCTION": [],
            "Online clients confirmation": [],
            "Model aggregation": [],
            "Masked model generation" : [],
        }
        self._seed_sharing_start_time = None
        self._seed_sharing_verify_time = 0
        self._seed_sharing_verified_count = 0
        

    def kernelStarting(self, startTime):
        """
        Called when the simulation starts.

        Args:
            startTime (pandas.Timestamp): The start time of the simulation.
        """
        

        # 动态导入 AggregatorAgent 以避免循环导入
        from agent.Aion.SA_Aggregator import SA_AggregatorAgent as AggregatorAgent
        self.AggregatorAgentID = self.kernel.findAgentByType(AggregatorAgent)

        self.setComputationDelay(0)
        
        # 初始化 seed sharing 状态
        self.kernel.custom_state['seed sharing'] = 0

        super().kernelStarting(startTime +
                               pd.Timedelta(self.random_state.randint(low=0, high=1000), unit='ns'))

    def kernelStopping(self):
        """
        Called when the simulation stops.
        """

        if self.id in self.user_committee:
            self.kernel.custom_state['seed sharing'] = self.timings["Seed sharing"][0]
            self.kernel.custom_state['Masked model generation'] = self.timings["REPORT"][0]

        super().kernelStopping()

    def wakeup(self, currentTime):
        """
        Called when the agent is awakened.

        Args:
            currentTime (pandas.Timestamp): The current simulation time.
        """

        self.report_time = time.time()
        super().wakeup(currentTime)
        dt_wake_start = pd.Timestamp('now')
        self.sendVectors(currentTime)
        self.report_time = time.time() - self.report_time


    def BFT_report(self, sign_message):
        """使用BFT协议进行报告"""
        # 准备阶段
        prepare_msg = self.bft_protocol.prepare(sign_message)
        
        # 签名消息
        msg_to_sign = dill.dumps(sign_message.body)
        hash_container = SHA256.new(msg_to_sign)
        signer = DSS.new(self.key, 'fips-186-3')
        signature = signer.sign(hash_container)
        
        # 创建BFT消息
        bft_msg = BFTMessage(
            type='prepare',
            value=sign_message,
            phase=BFTPhase.PREPARE,
            node_id=self.id,
            signature=signature
        )
        
        # 根据消息类型确定BFT消息类型
        bft_msg_type = "BFT_SIGN_LEGAL"
        if sign_message.body['msg'] == "ONLINE_CLIENTS":
            bft_msg_type = "BFT_SIGN_ONLINE"
        elif sign_message.body['msg'] == "FINAL_SUM":
            bft_msg_type = "BFT_SIGN_FINAL"
        
        # 发送给聚合器
        self.sendMessage(
            self.AggregatorAgentID,
            Message({
                "msg": bft_msg_type,
                "iteration": self.current_iteration,
                "sender": self.id,
                "bft_message": bft_msg,
                "sign_message": sign_message
            }),
            tag="comm_sign_client",
            msg_name=self.msg_name
        )

    def receiveMessage(self, currentTime, msg):
        """
        Called when the agent receives a message.

        Args:
            currentTime (pandas.Timestamp): The current simulation time.
            msg (Message): The received message.
        """
        super().receiveMessage(currentTime, msg)
        if msg.body["msg"] == "request shares sum":
            print(len(self.receive_mask_shares))
            if msg.body['iteration'] == self.current_iteration:
                dt_protocol_start = pd.Timestamp('now')
                self.reco_time = time.time()
                sum_shares = self.get_sum_shares(msg.body['request id list'])
                clt_comp_delay = pd.Timestamp('now') - dt_protocol_start
                self.sendMessage(self.AggregatorAgentID,
                                 Message({"msg": "hprf_SUM_SHARES",
                                          "iteration": self.current_iteration,
                                          "sender": self.id,
                                          "sum_shares": sum_shares,
                                          }),
                                 tag="comm_secret_sharing",
                                 msg_name=self.msg_name)

                self.recordTime(dt_protocol_start, 'RECONSTRUCTION')
                self.reco_time = time.time() - self.reco_time
                self.recordTime(dt_protocol_start, 'RECONSTRUCTION')

        elif msg.body["msg"] == "REQ" and self.current_iteration != 0:
            self.current_iteration += 1
            if self.current_iteration > self.no_of_iterations:
                return

            dt_protocol_start = pd.Timestamp('now')
            self.sendVectors(currentTime)
            self.recordTime(dt_protocol_start, "REPORT")

        elif msg.body["msg"] in ["BFT_SIGN_ONLINE", "BFT_SIGN_FINAL", "BFT_SIGN_LEGAL"]:
            # 处理BFT消息
            bft_msg = msg.body['bft_message']
            
            # 验证消息
            if not self._verify_bft_message(bft_msg):
                return
            
            # 处理消息并可能产生响应
            response = self.bft_protocol.handle_message(bft_msg)
            if response:
                # 签名响应
                response.signature = self._sign_bft_message(response)
                
                # 根据消息类型确定响应类型
                response_type = "BFT_RESPONSE_LEGAL"
                if msg.body["msg"] == "BFT_SIGN_ONLINE":
                    response_type = "BFT_RESPONSE_ONLINE"
                elif msg.body["msg"] == "BFT_SIGN_FINAL":
                    response_type = "BFT_RESPONSE_FINAL"
                
                # 发送响应
                self.sendMessage(
                    self.AggregatorAgentID,
                    Message({
                        "msg": response_type,
                        "iteration": self.current_iteration,
                        "sender": self.id,
                        "bft_message": response
                    }),
                    tag="comm_sign_client",
                    msg_name=self.msg_name
                )

        elif msg.body["msg"] == "SHARED_MASK":
            vss_start_time = time.time()
            sender_id = msg.body['sender']
            temp_shared_mask = msg.body['shared_mask']
            commitments = msg.body['commitments']
            
            # 存储份额和承诺
            self.receive_mask_shares[sender_id] = temp_shared_mask
            self.mask_commitments[sender_id] = commitments
            # 检查是否收到足够的份额
            if len(self.receive_mask_shares) == self.num_clients:
                vss_start_time = time.time()
                self.flag = 1
                shares = list(self.receive_mask_shares.values())
                all_commitments = list(self.mask_commitments.values())

                # ----------- 利用同态性批量验证 -----------
                # 计算所有份额的f、r累加
                total_f = 0
                total_r = 0
                for share in shares:
                    # 修改这里的解包方式
                    if isinstance(share, tuple) and len(share) == 3:
                        _, f_x, r_x = share
                        total_f = (total_f + f_x) % self.vss.q
                        total_r = (total_r + r_x) % self.vss.q
                    else:
                        self.agent_print(f"Invalid share format: {share}")
                        continue

                # 计算所有commitments的乘积
                C_mul = 1
                for cmt in all_commitments:
                    for c in cmt:
                        C_mul = (C_mul * c) % self.vss.p

                # 计算 g^total_f * h^total_r mod p
                C_sum = (gmpy2.powmod(self.vss.g, total_f, self.vss.p) * 
                        gmpy2.powmod(self.vss.h, total_r, self.vss.p)) % self.vss.p

                # # 验证同态性质
                # if C_mul == C_sum:
                #     self.agent_print("All shares verified successfully in batch (homomorphic)")
                # else:
                #     self.agent_print("Invalid shares detected in batch verification (homomorphic)")
                
                # self.timings["Seed sharing"][0] += (time.time() - vss_start_time)

        else:
            self.agent_print(f"Unknown message type: {msg.body['msg']}")

    def sendVectors(self, currentTime):
        """
        Sends the vectors to the server.

        Args:
            currentTime (pandas.Timestamp): The current simulation time.
        """
        if self.current_iteration == 1:
            # self.mask_seed = random.SystemRandom().randint(1, 10000)
            self.mask_seed = 10
            self.share_mask_seed()

        # 只统计本地计算时间
        compute_start = time.time()
        
        initialization_values_filename = r"agent\\HPRF\\initialization_values"
        n, m, p, q = load_initialization_values(initialization_values_filename)
        filename = r"matrix"
        shprg = SHPRG(n, m, p, q, filename)

        mask_vector = shprg.hprf(self.mask_seed, self.current_iteration, self.vector_len)

        mask_vector = np.array(mask_vector, dtype=np.uint32)

        vec = np.ones(self.vector_len, dtype=self.vector_dtype)
        masked_vec = vec + mask_vector

        compute_time = time.time() - compute_start
        self.timings["REPORT"].append(compute_time)

        self.sendMessage(self.AggregatorAgentID,
                         Message({"msg": "VECTOR",
                                  "iteration": self.current_iteration,
                                  "sender": self.id,
                                  "masked_vector": masked_vec,
                                  }),
                         tag="comm_key_generation",
                         msg_name=self.msg_name)

    def share_mask_seed(self):
        """
        Generates and shares the mask seed using verifiable secret sharing.
        """
        compute_start = time.time()
        
        # 检查user_committee
        if not self.user_committee:
            self.agent_print(f"Error: user_committee is empty for client {self.id}")
            return
        
        # 统一使用委员会大小的1/3作为阈值
        threshold = max(2, len(self.user_committee) // 3)   
        # 生成份额
        shares, commitments = self.vss_share(self.mask_seed, 
                                            len(self.user_committee),
                                            threshold, 
                                            self.prime)
        
        
        compute_time = time.time() - compute_start
        self.timings["Seed sharing"].append(compute_time)
        
        # 发送份额给委员会成员，添加重试机制
        user_committee_list = list(self.user_committee)
        for j, share in enumerate(shares):
            self.sendMessage(user_committee_list[j],
                                        Message({"msg": "SHARED_MASK",
                                                "sender": self.id,
                                                "shared_mask": share,
                                                "commitments": commitments,
                                                }),
                                        tag="comm_secret_sharing",
                                        msg_name=self.msg_name)
                    
        # self.agent_print(f"客户端{self.id}发送份额给委员会成员{user_committee_list[j]}: {share}")
        

    def generate_shares(secret, num_shares, threshold, prime, seed=None):
        """
        Generates secret shares.

        Args:
            secret: The secret to be shared.
            num_shares: The number of shares to generate.
            threshold: The number of shares required to reconstruct the secret.
            prime: The prime number to use.
            seed: An optional seed for the random number generator.

        Returns:
            shares: A list of secret shares in the format [(share_index, share_value)].
        """
        if seed is not None:
            random.seed(seed)
        coefficients = [secret] + [random.SystemRandom().randrange(1, prime) for _ in range(threshold - 1)]
        polynomial = lambda x: sum([coeff * x ** i for i, coeff in enumerate(coefficients)])
        shares = [(x, polynomial(x) % prime) for x in range(1, num_shares + 1)]
        return shares

    def vss_share(self, secret, num_shares: int, threshold: int = None, prime=None, seed=None):
        """
        Verifiable secret sharing function.

        Args:
            secret: The secret to be shared.
            num_shares: The number of shares to generate.
            threshold: The number of shares required to reconstruct the secret. Defaults to num_shares//3.
            prime: The prime number to use.
            seed: An optional seed for the random number generator.

        Returns:
            shares: A list of secret shares in the format [(share_index, share_value)].
            commitments: A list of commitments for verification.
        """
        if threshold is None:
            threshold = max(2, num_shares // 3)  # 确保阈值至少为2
        if prime is None:
            prime = self.prime
            
        # Use VSS to share the secret
        shares, commitments = self.vss.share(secret, num_shares, threshold, prime)
        return shares, commitments
        
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

    def sum_shares(shares_list, prime):
        """Sums multiple secret shares."""
        sum_shares = []
        sum_value = 0
        for share in shares_list:
            if share == 0:
                continue
            sum_value += share[1]
        sum_value = sum_value % prime
        i = 0
        while 1:
            if shares_list[i] == 0:
                i += 1
                continue
            sum_shares.append((shares_list[i][0], sum_value))
            break
        return sum_shares

    def get_sum_shares(self, client_id_list):
        """
        Sums the secret shares.

        Args:
            client_id_list (list): List of client IDs.

        Returns:
            sum_shares: The sum of the secret shares.
        """
        # 只统计本地计算时间
        compute_start = time.time()
        # print("client_id_list", client_id_list)
        
        # print(f"Client {self.id} 得到的分享值", self.receive_mask_shares)
        shares = []
        for i in range(len(client_id_list)):
            if client_id_list[i] in self.receive_mask_shares:
                shares.append(self.receive_mask_shares[client_id_list[i]])

        # print("shares", shares)

        sum_shares = SA_ClientAgent.sum_shares(shares, self.prime)
        
        compute_time = time.time() - compute_start
        self.timings["RECONSTRUCTION"].append(compute_time)


        
        return sum_shares


    def recordTime(self, startTime, categoryName):
        """
        Records the time.

        Args:
            startTime (pandas.Timestamp): The start time.
            categoryName (str): The category name.
        """
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime

    def agent_print(*args, **kwargs):
        """
        Custom print function that adds a [Server] header before printing.

        Args:
            *args: Any positional arguments accepted by the built-in print function.
            **kwargs: Any keyword arguments accepted by the built-in print function.
        """
        print(*args, **kwargs)

    def _verify_bft_message(self, msg: BFTMessage) -> bool:
        """验证BFT消息"""
        # 验证消息签名
        try:
            return self._verify_signature(msg)
        except:
            return False

    def _sign_bft_message(self, msg: BFTMessage) -> str:
        """签名BFT消息"""
        msg_to_sign = dill.dumps({
            'type': msg.type,
            'value': msg.value,
            'phase': msg.phase,
            'node_id': msg.node_id,
            'view': msg.view,
            'sequence': msg.sequence
        })
        hash_container = SHA256.new(msg_to_sign)
        signer = DSS.new(self.key, 'fips-186-3')
        return signer.sign(hash_container)

    def _verify_signature(self, msg: BFTMessage) -> bool:
        """验证消息签名"""
        msg_to_verify = dill.dumps({
            'type': msg.type,
            'value': msg.value,
            'phase': msg.phase,
            'node_id': msg.node_id,
            'view': msg.view,
            'sequence': msg.sequence
        })
        hash_container = SHA256.new(msg_to_verify)
        verifier = DSS.new(self.key, 'fips-186-3')
        try:
            verifier.verify(hash_container, msg.signature)
            return True
        except:
            return False

    def _handle_consensus(self, value):
        """处理达成的共识"""
        if isinstance(value, dict) and 'msg' in value:
            if value['msg'] == "VALID_CLIENTS":
                # 处理有效客户端集合共识
                self.valid_clients = value['valid_clients']
            elif value['msg'] == "ONLINE_CLIENTS":
                # 处理在线客户端集合共识
                self.online_clients = value['online_clients']
            elif value['msg'] == "FINAL_SUM":
                # 处理全局模型共识
                self.final_sum = value['final_sum']
                self.current_iteration += 1
