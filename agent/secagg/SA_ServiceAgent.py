# malicious version
from multiprocessing.sharedctypes import Value

from matplotlib.pyplot import axis
from scipy.fftpack import idstn
from agent.Agent import Agent
from message.Message import Message

import logging
import time
import dill

import math
import nacl.secret
import nacl.utils

import numpy as np
import pandas as pd
import random

from util import param
from util.crypto import ecchash
# from util.crypto.secretsharing import secret_int_to_points, points_to_secret_int
from util.crypto.secretsharing.simple_sharing import share_secret, reconstruct_secret

from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256


# Secret sharing for each client and the server
# import Crypto.Protocol.SecretSharing as shamir

# NEW MESSAGES: CLIENT_WEIGHTS : weights, SHARED_WEIGHTS : weights

# The PPFL_ServiceAgent class inherits from the base Agent class.  It provides
# the simple shared service necessary for model combination under secure
# federated learning.


class SA_ServiceAgent(Agent):

    def __init__(self, id, name, type,
                 random_state=None,
                 msg_fwd_delay=1000000,
                 round_time=pd.Timedelta("10s"),
                 field_size=-1,
                 iterations=4,
                 num_clients=10,
                 num_neighbors=-1,
                 neighbor_threshold=-1,
                 users={},
                 debug_mode=0,
                 max_input=10000,
                 vector_len=1024):

        # Base class init.
        super().__init__(id, name, type, random_state)

        self.logger = logging.getLogger("Log")
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig()

        # Set parameters
        self.num_clients = num_clients
        self.vector_len = vector_len
        self.vector_dtype = 'uint32'
        self.vec_sum_partial = np.zeros(self.vector_len, dtype=self.vector_dtype)
        self.prime = ecchash.n
        # 添加秘密分享使用的素数
        self.secret_sharing_prime = param.SECRET_SHARING_PRIME

        self.system_sk = None
        hdr = 'pki_files/system_pk.pem'
        f = open(hdr, "rt")
        key = ECC.import_key(f.read())
        f.close()
        self.system_sk = key.d

        # How long does it take us to forward a peer-to-peer client relay message?
        self.msg_fwd_delay = msg_fwd_delay
        self.round_time = round_time

        # Agent accumulation of elapsed times by category of task.
        self.elapsed_time = {'ADKEY': pd.Timedelta(0),
                             'GRAPH': pd.Timedelta(0),
                             'SHARE': pd.Timedelta(0),
                             'COLLECTION': pd.Timedelta(0),
                             'CROSSCHECK': pd.Timedelta(0),
                             'RECONSTRUCTION': pd.Timedelta(0),
                             }

        # How many iterations of the protocol should be run?
        self.no_of_iterations = iterations


        # The list of all users id
        self.users = users 

        self.neighbors = {} 

        self.user_vectors = {}
        self.recv_user_vectors = {}
    
        self.recv_user_pubkeys = {}
        self.user_pubkeys = {}

        self.user_choice = {}
        self.recv_user_choice = {}

        self.backup_shares_ai = {}
        self.recv_backup_shares_ai = {}

        self.backup_shares_mi = {}
        self.recv_backup_shares_mi = {}
        
        self.online_set = set()
        self.offline_set = set()

        self.ack = {}
        self.recv_ack = {}

        self.recon_shares_mi = {}
        self.recv_recon_shares_mi = {}
        self.recon_shares_ai = {}
        self.recv_recon_shares_ai = {}
        self.recon_index = {}
        self.recv_recon_index = {}
        
        # 添加一致性检查相关变量
        self.consistency_signatures = {}
        self.recv_consistency_signatures = {}
        self.proposed_online_set = set()
        self.proposed_offline_set = set()
       
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_hash = 0
        self.current_round = 0

        # Mapping the message processing functions
        self.aggProcessingMap = {
            0: self.init_func,
            1: self.advertise_keys,
            2: self.establish_graph,
            3: self.forward_shares,
            4: self.collection,
            5: self.check_alive,
            6: self.consistency_check,
            7: self.reconstruction,
        }

        self.namedict = {
            0: "init_func",
            1: "advertise_keys",
            2: "establish_graph",
            3: "forward_shares",
            4: "collection",
            5: "check_alive",
            6: "consistency_check",
            7: "reconstruction",
        }
    # Simulation lifecycle messages.

    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['srv_adkey'] = pd.Timedelta(0)
        self.kernel.custom_state['srv_graph'] = pd.Timedelta(0)
        self.kernel.custom_state['srv_share'] = pd.Timedelta(0)

        self.kernel.custom_state['srv_collection'] = pd.Timedelta(0)
        self.kernel.custom_state['srv_crosscheck'] = pd.Timedelta(0)
        self.kernel.custom_state['srv_reconstruction'] = pd.Timedelta(0)

        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        
        self.kernel.custom_state['srv_adkey'] += (
            self.elapsed_time['ADKEY'] / self.no_of_iterations)
        self.kernel.custom_state['srv_graph'] += (
            self.elapsed_time['GRAPH'] / self.no_of_iterations)
        self.kernel.custom_state['srv_share'] += (
            self.elapsed_time['SHARE'] / self.no_of_iterations)
        
        self.kernel.custom_state['srv_collection'] += (
            self.elapsed_time['COLLECTION'] / self.no_of_iterations)
        self.kernel.custom_state['srv_crosscheck'] += (
            self.elapsed_time['CROSSCHECK'] / self.no_of_iterations)
        self.kernel.custom_state['srv_reconstruction'] += (
            self.elapsed_time['RECONSTRUCTION'] / self.no_of_iterations)

        # Allow the base class to perform stopping activities.
        super().kernelStopping()

    # Simulation participation messages.

    # The service agent wakeup at the end of each round
    # More specifically, it stores the messages on receiving the msgs;
    # When the timing out happens, or it collects enough number of msgs,
    # (i.e., from all clients it is waiting for),
    # it starts processing and replying the messages.

    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        print("server wakeup in iteration",
              self.current_iteration,
              "at func", self.namedict[self.current_round],
              "currentTime", currentTime)

        # In the k-th iteration
        self.aggProcessingMap[self.current_round](currentTime)

    # On receiving messages

    def receiveMessage(self, currentTime, msg):
        # Allow the base Agent to do whatever it needs to.
        super().receiveMessage(currentTime, msg)

        # Get the sender's id
        sender_id = msg.body['sender']

        if msg.body['msg'] == "PUBKEY":
            dt_protocol_start = pd.Timestamp('now')

            if msg.body['iteration'] == self.current_iteration:
         
                self.recv_user_pubkeys[sender_id] = msg.body['pubkey'] 
               
            else:
                print("Server receives PUBKEY from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

        elif msg.body['msg'] == "CHOICE":
            dt_protocol_start = pd.Timestamp('now')

            if msg.body['iteration'] == self.current_iteration:
                
                # store who chooses each client
                self.recv_user_choice[sender_id] = msg.body['choice']
                 
            else:
                print("Server receives CHOICE from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

        elif msg.body['msg'] == "BACKUP":
            
            if msg.body['iteration'] == self.current_iteration:
                
                # store who chooses each client
                self.recv_backup_shares_ai[sender_id] = msg.body['backup_shares_ai']
                self.recv_backup_shares_mi[sender_id] = msg.body['backup_shares_mi']
                
            else:
                print("Server receives BACKUP from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

        elif msg.body['msg'] == "VECTOR":

            dt_protocol_start = pd.Timestamp('now')

            if msg.body['iteration'] == self.current_iteration:
                
                # Store the vectors
                self.recv_user_vectors[sender_id] = msg.body['vector']
                
            else:
                print("Server receives VECTORS from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

            # Accumulate into offline setup.
            self.recordTime(dt_protocol_start, "COLLECTION")
        
        elif msg.body['msg'] == "ACK":
            dt_protocol_start = pd.Timestamp('now')
            
            if msg.body['iteration'] == self.current_iteration:
                self.recv_ack[sender_id] = msg.body['ack']
            else:
                print("Server receives ACK from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

        elif msg.body['msg'] == "SHARES":
            
            dt_protocol_start = pd.Timestamp('now')
            
            if msg.body['iteration'] == self.current_iteration:
                
                if len(msg.body['shares_of_mi']) != 0:
                    self.recv_recon_shares_mi[sender_id] = msg.body['shares_of_mi']
                if len(msg.body['shares_of_ai']) != 0:
                    self.recv_recon_shares_ai[sender_id] = msg.body['shares_of_ai']
                
            else:
                print("Server receives SHARED_RESULT from iteration", msg.body['iteration'],
                      " client ", msg.body['sender'])

            
            self.recordTime(dt_protocol_start, "RECONSTRUCTION")

        elif msg.body['msg'] == "CONSISTENCY_SIG":
            dt_protocol_start = pd.Timestamp('now')
            
            if msg.body['iteration'] == self.current_iteration:
                # 收集客户端的签名确认
                self.recv_consistency_signatures[sender_id] = msg.body['signature']
            
            self.recordTime(dt_protocol_start, "CROSSCHECK")

    # NOTE: the currentTime is the 'start' of the function

    # Processing and replying the messages.
    def init_func(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
      
        self.current_round = 1
        
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.setWakeup(currentTime + server_comp_delay + pd.Timedelta('3s'))

    def advertise_keys_read_from_pool(self):
        self.user_pubkeys = self.recv_user_pubkeys
        self.recv_user_pubkeys = {}
    
    def advertise_keys_clear_pool(self):
        # Empty the pool for upcoming messages 
        # before server sends requests
        self.recv_user_choice = {}

    def advertise_keys(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.advertise_keys_read_from_pool()
       
        print("Server collected #pubkeys =", len(self.user_pubkeys))

        self.advertise_keys_clear_pool()

        # send to users who send their pubkeys
        for id in self.user_pubkeys:
            self.sendMessage(id,
                             Message({"msg": "REQ_CHOICE",
                                      "iteration": self.current_iteration,
                                      "sender": 0,
                                      "active_pubkey_clients": list(self.user_pubkeys.keys()),
                                      }),
                             tag="comm_active_clients")
        
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for advertise_keys:", server_comp_delay)

        self.recordTime(dt_protocol_start, "ADKEY")

        # print serialization size
        if __debug__:
            tmp_pubkeys = {}
            for i in self.user_pubkeys:
                tmp_pubkeys[i] = (int(self.user_pubkeys[i].x), int(self.user_pubkeys[i].y))
            self.logger.info(f"Server pubkey comm cost: {len(dill.dumps(tmp_pubkeys))}")

        self.current_round = 2

        self.setWakeup(currentTime + server_comp_delay + param.wt_google_graph)

    def establish_graph_read_from_pool(self):
        # send who chose id to client id
        self.user_choice = self.recv_user_choice
        self.recv_user_choice = {}

    def establish_graph_clear_pool(self):
        return

    def establish_graph(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.establish_graph_read_from_pool()
      
        print("Server collected #graph choice =", len(self.recv_user_choice))

        # 修改为全连接图
        self.neighbors = {}  
        for i in self.user_choice:
            # 每个客户端与所有其他客户端连接
            self.neighbors[i] = set(self.user_choice.keys())
            if i in self.neighbors[i]:
                self.neighbors[i].remove(i)

        # neighbors_pubkeys[i] stores client i's neighbors pubkeys
        neighbors_pubkeys = {}
        for id in self.user_choice:
            # 为每个客户端提供所有其他客户端的公钥
            tmpls = {}
            for j in self.neighbors[id]:
                tmpls[j] = self.user_pubkeys[j]
            neighbors_pubkeys[id] = tmpls

        print("number of active choice clients:", len(self.user_choice.keys()))

        for id in self.user_choice:
            self.sendMessage(id,
                             Message({"msg": "REQ_BACKUP",
                                      "iteration": self.current_iteration,
                                      "sender": 0,
                                      "neighbors": self.neighbors[id],
                                      "neighbors_pubkeys": neighbors_pubkeys[id],
                                      "active_choice_clients": list(self.user_choice.keys()),
                                      }),
                             tag="comm_graph_server")
        
        self.current_round = 3

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for establish_graph:", server_comp_delay)

        self.recordTime(dt_protocol_start, "GRAPH")

        if __debug__:
            tmp_pubkeys = {}
            for i in self.user_choice:
                tmp_pubkeys[i] = {}
                for j in neighbors_pubkeys[i]:
                    tmp_pubkeys[i][j] = (int(neighbors_pubkeys[i][j].x), int(neighbors_pubkeys[i][j].y))
            tmp_neighbor_ids = {}
            for i in self.user_choice:
                tmp_neighbor_ids[i] = self.neighbors[i] 
            self.logger.info(f"Server graph choice comm cost: {len(dill.dumps(tmp_pubkeys)) + len(dill.dumps(tmp_neighbor_ids))}")
       
        self.setWakeup(currentTime + server_comp_delay + param.wt_google_share) 
    
    def forward_signatures_read_from_pool(self):
        # self.backup_shares_ai[id] is the shares from client id
        # the server should forward the shares to id's neighbors
        self.backup_shares_ai = self.recv_backup_shares_ai
        self.recv_backup_shares_ai = {}

        self.backup_shares_mi = self.recv_backup_shares_mi
        self.recv_backup_shares_mi = {}

    def forward_signatures_clear_pool(self):
        self.recv_user_vectors = {}

    def forward_shares(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.forward_signatures_read_from_pool()

        # 修改为全连接图下的份额转发
        forward_shares_ai = {}
        forward_shares_mi = {}
        
        # 初始化所有客户端的份额存储
        for i in self.backup_shares_ai:
            for j in self.neighbors[i]:
                if j not in forward_shares_ai:
                    forward_shares_ai[j] = {}
                if j not in forward_shares_mi:
                    forward_shares_mi[j] = {}

        # 分配份额
        for i in self.backup_shares_ai:
            if len(self.neighbors[i]) != len(self.backup_shares_ai[i]):
                raise ValueError("#of shares does not match #neighbors.")
            cnt = 0
            for j in self.neighbors[i]:
                forward_shares_ai[j][i] = self.backup_shares_ai[i][cnt]
                forward_shares_mi[j][i] = self.backup_shares_mi[i][cnt]
                cnt += 1

        self.forward_signatures_clear_pool()

        # 请求向量
        for id in self.user_choice:
            self.sendMessage(id,
                             Message({"msg": "REQ_VECTOR",
                                      "iteration": self.current_iteration,
                                      "sender": 0,
                                      "backup_shares_ai": forward_shares_ai[id],
                                      "backup_shares_mi": forward_shares_mi[id],
                                      }),
                             tag="comm_graph_server")

        self.current_round = 4

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for forward_shares:", server_comp_delay)

        self.recordTime(dt_protocol_start, "SHARE")

        if __debug__:
            tmp_shares = {}
            for i in self.user_choice:
                tmp_shares[i] = {}
                for j in forward_shares_ai[i]:
                    tmp_shares[i][j] = (int(forward_shares_ai[i][j][1]), int(forward_shares_mi[i][j][1]))
            
            self.logger.info(f"Server forward shares comm cost: {len(dill.dumps(tmp_shares))}")
        
        self.setWakeup(currentTime + server_comp_delay + param.wt_google_collection)

    def collection_read_from_pool(self):
        # assign user vectors to a new var. empty user vectors immediately.
        self.user_vectors = self.recv_user_vectors
        self.recv_user_vectors = {}
    
    def collection_clear_pool(self):
        self.recv_ack = {}

    def collection(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')

        self.collection_read_from_pool()
        print("collected vectors =", len(self.user_vectors))
        
        # compute the sum of vectors
        self.vec_sum_partial = np.zeros(self.vector_len, dtype=self.vector_dtype)
        for id in self.user_vectors:
            if len(self.user_vectors[id]) != self.vector_len:
                raise ValueError("Client sends inconsistent vector length")
            self.vec_sum_partial += self.user_vectors[id] 

        # here should request alive signatures
        # server should send to the clients who is alive
        self.collection_clear_pool()
        for id in self.user_vectors:
            self.sendMessage(id,
                             Message({"msg": "REQ_ACK",
                                      "iteration": self.current_iteration,
                                      "request_ack": 1,
                                      "alive_set": self.user_vectors,
                                      }),
                             tag="comm_ack_server")


        self.current_round = 5
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for collection:", server_comp_delay)

        self.recordTime(dt_protocol_start, "COLLECTION")

         # print serialization cost
        if __debug__:
            self.logger.info(f"Server comm for collecting vectors: {len(dill.dumps(self.user_vectors))}")

        self.setWakeup(currentTime + server_comp_delay + param.wt_google_crosscheck)

    def check_alive_read_from_pool(self):
        self.ack = self.recv_ack
        self.recv_ack = {}
    
    def check_alive_clear_pool(self):
        self.recv_recon_shares_mi = {}
        self.recv_recon_shares_ai = {}

    def check_alive(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.check_alive_read_from_pool()

        # pack the in edge to i, send ack to i
        in_neighbors_ack = {}
        for i in self.ack:
            for j in self.ack[i]:
                in_neighbors_ack[j] = {}

        for sender in self.ack:
            for recvr in self.ack[sender]:
                in_neighbors_ack[recvr][sender] = self.ack[sender][recvr]
        
        self.online_set = set(self.user_vectors.keys())
        # print("online clients:", len(self.online_set))

        self.offline_set = set(self.user_choice) - set(self.online_set)
        # print("offline clients:", len(self.offline_set))

        # request_mi_shares[id] is a list, storing neighbors to be request 
        # id will receive this, and send to the server the shares of the requested neighbors
        request_mi_shares = {}  
        request_ai_shares = {}

        # for id in online set, request id's neighbor for shares of mi
        for i in self.user_choice:
            request_mi_shares[i] = []
        
        for i in self.online_set:
            for j in self.neighbors[i]:
                request_mi_shares[j].append(i)

        # for id in offline set, request id's neighbor for shares of ai
        for i in self.user_choice:
            request_ai_shares[i] = []
        
        for i in self.offline_set:
            for j in self.neighbors[i]:
                request_ai_shares[j].append(i)
        
        self.check_alive_clear_pool()

        for id in self.user_vectors:
            self.sendMessage(id,
                             Message({"msg": "REQ_SHARES",
                                      "iteration": self.current_iteration,
                                      "neighbors_ack": in_neighbors_ack[id], 
                                      "request_mi_shares": request_mi_shares,
                                      "request_ai_shares": request_ai_shares,
                                      }),
                             tag="comm_dec_server")

        self.current_round = 6
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for check_alive:", server_comp_delay)

        self.recordTime(dt_protocol_start, "CROSSCHECK")
    
        if __debug__:
            # print serialization cost 
            self.logger.info(f"Server forward ACK comm: {len(dill.dumps(in_neighbors_ack))}")
            self.logger.info(f"Server comm for requesting shares: {len(dill.dumps(request_ai_shares)) + len(dill.dumps(request_mi_shares))}")

        self.setWakeup(currentTime + server_comp_delay + param.wt_google_recontruction)

    def reconstruction_read_from_pool(self):
        self.recon_shares_mi = self.recv_recon_shares_mi
        self.recv_recon_shares_mi = {}

        self.recon_shares_ai = self.recv_recon_shares_ai
        self.recv_recon_shares_ai = {}

    def reconstruction_clear_pool(self):
        return 

    def reconstruction(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.reconstruction_read_from_pool()

        # 验证一致性签名
        if len(self.recv_consistency_signatures) < len(self.user_vectors):
            print("Not enough consistency signatures received")
            # return

        # 验证每个签名
        for id in self.recv_consistency_signatures:
            if id not in self.user_pubkeys:
                continue
            # try:
            #     verifier = DSS.new(self.user_pubkeys[id], 'fips-186-3')
            #     consistency_msg = str.encode(str(id) + str(sorted(self.proposed_online_set)) + str(sorted(self.proposed_offline_set)))
            #     h = SHA256.new(consistency_msg)
            #     verifier.verify(h, self.recv_consistency_signatures[id])
            # except:
                # print(f"Invalid consistency signature from client {id}")
                # return

        """Reconstruct mi for client i."""
        for i in self.online_set:
            mi_shares = []  # shares of mi for this client i
            for j in self.recon_shares_mi:
                if i in self.recon_shares_mi[j]:
                    mi_shares.append(self.recon_shares_mi[j][i])
            
            if len(mi_shares) < math.ceil(len(self.neighbors[i]) / 2):
                print(f"Not enough shares to reconstruct mi for client {i}")
                continue
                
            # 使用简单秘密分享重建mi
            mi_recon = reconstruct_secret(mi_shares, self.secret_sharing_prime)
            # print(f"\n=== 服务器重建客户端 {i} 的个体掩码种子 ===")
            # print(f"重建的个体掩码种子: {mi_recon}")
            
            # 将重建的mi转换为16字节用于PRG
            mi_bytes = (mi_recon & ((1 << 128) - 1)).to_bytes(16, 'big')
            # print(f"重建的个体掩码种子(hex): {mi_bytes.hex()}")
            
            # 使用mi_bytes生成PRG
            prg_mi_holder = AES.new(mi_bytes, AES.MODE_CBC, iv=b"0123456789abcdef")
            data = param.fixed_key * self.vector_len
            prg_mi = prg_mi_holder.encrypt(data)
            
            # 将PRG输出转换为向量
            vec_prg_mi = np.frombuffer(prg_mi, dtype=self.vector_dtype)
            # print(f"重建的个体掩码向量: {vec_prg_mi}")

            # 从部分和中减去个体掩码
            self.vec_sum_partial = self.vec_sum_partial - vec_prg_mi
            # print(f"服务器减去客户端 {i} 的掩码向量: {vec_prg_mi[:5]}...")

        for i in self.offline_set:
            ai_shares = []
            for j in self.recon_shares_ai:
                if i in self.recon_shares_ai[j]:
                    ai_shares.append(self.recon_shares_ai[j][i])

            if len(ai_shares) < math.ceil(len(self.neighbors[i]) / 2):
                print(f"Not enough shares to reconstruct ai for client {i}")
                continue

            # 使用secret_sharing_prime进行重建
            ai_recon = reconstruct_secret(ai_shares, self.secret_sharing_prime)

            # 计算与所有在线客户端的成对密钥
            pairwise_keys = {}
            for j in self.online_set:
                if j != i:
                    pairwise_keys[j] = int(ai_recon) * self.user_pubkeys[j]
            
            # 计算掩码
            prg_pairwise = {}
            vec_prg_pairwise = {}
            for j in pairwise_keys:
                pairwise_seed = (int(pairwise_keys[j].x) & (1<<128) - 1).to_bytes(16, 'big')
                    
                prg_pairwise_holder = AES.new(pairwise_seed, AES.MODE_CBC, iv=b"0123456789abcdef")
                data = param.fixed_key * self.vector_len
 
                prg_pairwise[j] = prg_pairwise_holder.encrypt(data)                
                vec_prg_pairwise[j] = np.frombuffer(prg_pairwise[j], dtype=self.vector_dtype)
                    
                # 解掩码向量
                if len(vec_prg_pairwise[j]) != self.vector_len:
                    raise ValueError("vector length error")
                if i < j:
                    self.vec_sum_partial = self.vec_sum_partial + vec_prg_pairwise[j]
                elif i > j:
                    self.vec_sum_partial = self.vec_sum_partial - vec_prg_pairwise[j]
                else:
                    raise ValueError("self.id =", self.id, " should not appear in neighbors", self.neighbors)

        self.vec_sum_partial = self.vec_sum_partial / len(self.online_set)
        print("final sum =", self.vec_sum_partial)

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for reconstruction:", server_comp_delay)

        self.recordTime(dt_protocol_start, "RECONSTRUCTION")

        if __debug__:
            tmp_recon_ai = {}
            for i in self.recon_shares_ai:
                tmp_recon_ai[i] = {}
                for j in self.recon_shares_ai[i]:
                    tmp_recon_ai[i][j] = int(self.recon_shares_ai[i][j][1])
        
            tmp_recon_mi = {}
            for i in self.recon_shares_mi:
                tmp_recon_mi[i] = {}
                for j in self.recon_shares_mi[i]:
                    tmp_recon_mi[i][j] = int(self.recon_shares_mi[i][j][1])
            self.logger.info(f"Server comm for recv recon shares: {len(dill.dumps(tmp_recon_ai)) + len(dill.dumps(tmp_recon_mi))}")

        print()
        print("######## Iteration completion ########")
        print(f"[Server] finished iteration {self.current_iteration} at {currentTime + server_comp_delay}")
        print()
        
        # Reset iteration variables before sending REQ
        self.current_round = 1

        # End of the iteration
        self.current_iteration += 1

        if (self.current_iteration > self.no_of_iterations):
            return
        
        self.recv_user_pubkeys = {}

        for id in self.users:
            self.sendMessage(id,
                             Message({"msg": "REQ_PUBKEY",
                                      "iteration": self.current_iteration,
                                      "sender": 0,
                                      "output": 1,
                                      }),
                             tag="comm_output_server")

        self.setWakeup(currentTime + server_comp_delay + param.wt_google_adkey)

    def consistency_check(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        
        # 收集所有客户端的在线/离线状态
        self.proposed_online_set = set(self.user_vectors.keys())
        self.proposed_offline_set = set(self.user_choice.keys()) - self.proposed_online_set
        
        # 向所有客户端广播提议的在线/离线集合
        for id in self.user_choice:
            self.sendMessage(id,
                             Message({"msg": "REQ_CONSISTENCY",
                                      "iteration": self.current_iteration,
                                      "proposed_online_set": list(self.proposed_online_set),
                                      "proposed_offline_set": list(self.proposed_offline_set),
                                      }),
                             tag="comm_consistency_server")
        
        self.current_round = 7  # 移动到重建轮
        
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("Server time for consistency check:", server_comp_delay)
        
        self.recordTime(dt_protocol_start, "CROSSCHECK")
        
        self.setWakeup(currentTime + server_comp_delay + param.wt_google_recontruction)



# ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        # Accumulate into offline setup.
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime
        self.setComputationDelay(
            int((dt_protocol_end - startTime).to_timedelta64()))
