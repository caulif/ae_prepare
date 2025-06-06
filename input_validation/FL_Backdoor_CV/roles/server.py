import copy

import os
import pdb
import random
import re
from collections import defaultdict
import time


import numpy as np
import sklearn.metrics.pairwise as smp
import torch
import torch.nn.functional as F
from scipy.linalg import eigh as largest_eigh
from scipy.stats import entropy
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics import pairwise_distances
from torch.nn.utils import parameters_to_vector, vector_to_parameters

from FL_Backdoor_CV.models.create_model import create_model
from FL_Backdoor_CV.roles.evaluation import test_cv, test_poison_cv
from configs import args
from FL_Backdoor_CV.roles.aggregation_rules import aion
from FL_Backdoor_CV.roles.aggregation_rules import ACORN
from FL_Backdoor_CV.roles.aggregation_rules import avg
from FL_Backdoor_CV.roles.aggregation_rules import flame




def softmax(x):
    f_x = np.exp(x) / np.sum(np.exp(x))
    return f_x


class Server:
    def __init__(self, helper, clients, adversary_list):
        # === model ===
        if args.resume:
            self.model = torch.load(os.path.join('./FL_Backdoor_CV/saved_models/Revision_1', args.resumed_name),
                                    map_location=args.device)
        else:
            self.model = create_model()

        # === gradient correction ===
        self.previous_models = []
        if args.gradient_correction:
            previous_model = copy.deepcopy(self.model)
            previous_model.load_state_dict(self.model.state_dict())
            self.previous_models.append(previous_model)

        # === clients, participants, attackers, and benign clients ===
        self.clients = clients
        self.participants = None
        self.adversary_list = adversary_list
        self.benign_indices = list(set(list(range(args.participant_population))) - set(self.adversary_list))

        # === image helper ===
        self.helper = helper

        # === whether resume ===
        self.current_round = 0
        # === Inherent recognition accuracy on poisoned data sets
        self.inheret_poison_acc = 0

        if args.resume:
            self.current_round = int(re.findall(r'\d+\d*', args.resumed_name.split('/')[1])[0])
            test_l, test_acc = self.validate()
            if args.attack_mode.lower() == 'combine':
                test_l_acc = self.validate_poison()
                print(f"\n--------------------- T e s t - L o a d e d - M o d e l ---------------------")
                print(f"Accuracy on testset: {test_acc: .4f}, Loss on testset: {test_l: .4f}.")
                for i in range(args.multi_objective_num):
                    if i == 0:
                        print(f"Poison accuracy (o1): {test_l_acc[0][1]: .4f}.", end='   =========   ')
                    elif i == 1:
                        print(f"Poison accuracy (o2): {test_l_acc[1][1]: .4f}.")
                    elif i == 2:
                        print(f"Poison accuracy (o3): {test_l_acc[2][1]: .4f}.", end='   =========   ')
                    elif i == 3:
                        print(f"Poison accuracy (o4): {test_l_acc[3][1]: .4f}.")
                    elif i == 4:
                        print(f"Poison accuracy (wall ---> bird): {test_l_acc[4][1]: .4f}.")
                    elif i == 5:
                        print(f"Poison accuracy (green car ---> bird): {test_l_acc[5][1]: .4f}.")
                    elif i == 6:
                        print(f"Poison accuracy (strip car ---> bird): {test_l_acc[6][1]: .4f}.")
                print(f"--------------------- C o m p l e t e ! ---------------------\n")
            else:
                test_poison_loss, test_poison_acc = self.validate_poison()
                self.inheret_poison_acc = test_poison_acc
                print(f"\n--------------------- T e s t - L o a d e d - M o d e l ---------------------\n"
                      f"Accuracy on testset: {test_acc: .4f}, "
                      f"Loss on testset: {test_l: .4f}. <---> "
                      f"Poison accuracy: {test_poison_acc: .4f}, "
                      f"Poison loss: {test_poison_loss: .4f}"
                      f"\n--------------------- C o m p l e t e ! ---------------------\n")

        # === total data size ===
        self.total_size = 0

        # === whether poison ===
        self.poison_rounds = list()
        self.is_poison = args.is_poison
        if self.is_poison:
            # === give the poison rounds in the configuration ===
            if args.poison_rounds:
                assert isinstance(args.poison_rounds, str)
                self.poison_rounds = [int(i) for i in args.poison_rounds.split(',')]
            else:
                retrain_rounds = np.arange(self.current_round + 1 + args.windows,
                                           self.current_round + args.windows + args.retrain_rounds + 1)
                whether_poison = np.random.uniform(0, 1, args.retrain_rounds) >= (1 - args.poison_prob)
                self.poison_rounds = set((retrain_rounds * whether_poison).tolist())
                if 0 in self.poison_rounds:
                    self.poison_rounds.remove(0)
                self.poison_rounds = list(self.poison_rounds)
            args.poison_rounds = self.poison_rounds
            print(f"\n--------------------- P o i s o n - R o u n d s : {self.poison_rounds} ---------------------\n")
        else:
            print(f"\n--------------------- P o i s o n - R o u n d s : N o n e ! ---------------------\n")

        # === root dataset ===
        self.root_dataset = None
        if args.aggregation_rule.lower() == 'fltrust':
            # being_sampled_indices = list(range(args.participant_sample_size))
            # subset_data_chunks = random.sample(being_sampled_indices, 1)[0]
            # self.root_dataset = self.helper.benign_train_data[subset_data_chunks]
            self.root_dataset = self.helper.load_root_dataset()
        
        # === save path ===
        localtime = time.localtime(time.time())
        self.path = f"{args.dataset}_{args.attack_mode}_" \
               f"{localtime[1]:02}{localtime[2]:02}{localtime[3]:02}{localtime[4]:02}.txt"
        
        # === jzx test ===
        self.l2_norm, self.linf_norm, self.linf_norm_shprg, self.b, self.benign_index_list = [], 1, 1, 1, []
        
    def select_participants(self):
        self.current_round += 1
        self.total_size = 0
        if args.random_compromise:
            self.participants = random.sample(range(args.participant_population), args.participant_sample_size)
        else:
            if self.current_round in self.poison_rounds:
                if args.attack_mode.lower() == 'dba':
                    candidates = list()
                    adversarial_index = self.poison_rounds.index(self.current_round) % args.dba_trigger_num
                    for client_id in self.adversary_list:
                        if self.clients[client_id].adversarial_index == adversarial_index:
                            candidates.append(client_id)
                    self.participants = candidates + random.sample(
                        self.benign_indices, args.participant_sample_size - len(candidates))

                    # === calculate the size of participating examples ===
                    for client_id in self.participants:
                        self.total_size += self.clients[client_id].local_data_size
                    print(
                        f"Participants in round {self.current_round}: {[client_id for client_id in self.participants]}, "
                        f"Benign participants: {args.participant_sample_size - len(candidates)}, "
                        f"Total size: {self.total_size}")
                else:
                    self.participants = self.adversary_list + random.sample(
                        self.benign_indices, args.participant_sample_size - len(self.adversary_list))

                    # === calculate the size of participating examples ===
                    for client_id in self.participants:
                        self.total_size += self.clients[client_id].local_data_size
                    print(
                        f"Participants in round {self.current_round}: {[client_id for client_id in self.participants]}, "
                        f"Benign participants: {args.participant_sample_size - len(self.adversary_list)}, "
                        f"Total size: {self.total_size}")
            else:
                self.participants = random.sample(self.benign_indices, args.participant_sample_size)
                # === calculate the size of participating examples ===
                for client_id in self.participants:
                    self.total_size += self.clients[client_id].local_data_size
                print(f"Participants in round {self.current_round}: {[client_id for client_id in self.participants]}, "
                      f"Benign participants: {args.participant_sample_size}, "
                      f"Total size: {self.total_size}")

    def train_and_aggregate(self, global_lr):
        # === trained local models ===
        trained_models = dict()
        param_updates = list()
        trained_params = list()
        for client_id in self.participants:
            local_model = copy.deepcopy(self.model)
            local_model.load_state_dict(self.model.state_dict())
            trained_local_model = self.clients[client_id].local_train(local_model, self.helper, self.current_round)
            if args.aggregation_rule.lower() == 'fltrust':
                param_updates.append(parameters_to_vector(trained_local_model.parameters()) - parameters_to_vector(
                    self.model.parameters()))
            elif args.aggregation_rule.lower() == 'flame':
                trained_param = parameters_to_vector(trained_local_model.parameters()).detach().cpu()
                trained_params.append(trained_param)

            for name, param in trained_local_model.state_dict().items():
                if name not in trained_models:
                    trained_models[name] = param.data.view(1, -1)
                else:
                    trained_models[name] = torch.cat((trained_models[name], param.data.view(1, -1)),
                                                     dim=0)

        # === model updates ===
        # previous_model_params = None
        # previous_model_update = None
        # last_model_params = None
        # if args.gradient_correction:
        #     previous_model_params = self.previous_models[0].state_dict()
        #     previous_model_update = dict()
        #     last_model_params = dict()
        model_updates = dict()
        for (name, param), local_param in zip(self.model.state_dict().items(), trained_models.values()):
            model_updates[name] = local_param.data - param.data.view(1, -1)
            # if args.gradient_correction:
            #     previous_model_update[name] = param.data.view(1, -1) - previous_model_params[name].view(1, -1)
            #     last_model_params[name] = param.data.view(1, -1)
            if args.attack_mode.lower() in ['mr', 'dba', 'flip', 'edge_case', 'neurotoxin', 'combine']:
                if 'num_batches_tracked' not in name:
                    for i in range(args.participant_sample_size):
                        if self.clients[self.participants[i]].malicious:
                            mal_boost = 1
                            if args.is_poison:
                                if args.mal_boost:
                                    if args.attack_mode.lower() in ['mr', 'flip', 'edge_case', 'neurotoxin', 'combine']:
                                        mal_boost = args.mal_boost / args.number_of_adversaries
                                    elif args.attack_mode.lower() == 'dba':
                                        mal_boost = args.mal_boost / (args.number_of_adversaries / args.dba_trigger_num)
                                else:
                                    if args.attack_mode.lower() in ['mr', 'flip', 'edge_case', 'neurotoxin', 'combine']:
                                        mal_boost = args.participant_sample_size / args.number_of_adversaries
                                    elif args.attack_mode.lower() == 'dba':
                                        mal_boost = args.participant_sample_size / \
                                                    (args.number_of_adversaries / args.dba_trigger_num)
                            # model_updates[name][i] *= (mal_boost / args.global_lr)
                            model_updates[name][i] *= (mal_boost / args.global_lr / args.s_norm)

        # if args.gradient_correction:
        #     if len(self.previous_models) == args.windows:
        #         self.previous_models.pop(0)

        # === aggregate ===
        global_update = None

        if args.aggregation_rule.lower() == 'aion':
            global_update, self.l2_norm, self.linf_norm, self.linf_norm_shprg, self.b, benign_index \
                = aion(model_updates, self.l2_norm, self.linf_norm, self.linf_norm_shprg, self.b, self.current_round)            
        elif args.aggregation_rule.lower() == 'acorn':
            global_update, self.b = ACORN(model_updates, self.b, self.current_round)
        elif args.aggregation_rule.lower() == 'avg':
            global_update = avg(model_updates)
        elif args.aggregation_rule.lower() == 'flame':
            current_model_param = parameters_to_vector(self.model.parameters()).detach().cpu()
            global_param, global_update = flame(trained_params, current_model_param, model_updates)
            vector_to_parameters(global_param, self.model.parameters())
            model_param = self.model.state_dict()
            for name, param in model_param.items():
                if 'num_batches_tracked' in name or 'running_mean' in name or 'running_var' in name:
                    model_param[name] = param.data + global_update[name].view(param.size())
            self.model.load_state_dict(model_param)
            return

        # === update the global model ===
        model_param = self.model.state_dict()
        for name, param in model_param.items():
            model_param[name] = param.data + global_lr * global_update[name].view(param.size())
        self.model.load_state_dict(model_param)

    def validate(self):
        with torch.no_grad():
            test_l, test_acc = test_cv(self.helper.benign_test_data, self.model)
        return test_l, test_acc

    def validate_poison(self):
        with torch.no_grad():
            if args.attack_mode.lower() == 'combine':
                test_l_acc = []
                for i in range(args.multi_objective_num):
                    test_l, test_acc = test_poison_cv(self.helper, self.helper.poisoned_test_data,
                                                      self.model, adversarial_index=i)
                    test_l_acc.append((test_l, test_acc))
                return test_l_acc
            else:
                test_l, test_acc = test_poison_cv(self.helper, self.helper.poisoned_test_data, self.model)
                return test_l, test_acc