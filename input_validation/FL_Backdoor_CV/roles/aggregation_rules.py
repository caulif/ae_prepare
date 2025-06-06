import math
from collections import defaultdict
import os
import pdb
import re

import numpy as np
import sklearn.metrics.pairwise as smp
import torch
import torch.nn.functional as F
import hdbscan
from scipy.linalg import eigh as largest_eigh
from sklearn.cluster import DBSCAN, KMeans

from FL_Backdoor_CV.shprg.shprg import SHPRG, load_initialization_values
from configs import args


def avg(model_updates):
    global_update = dict()
    for name, data in model_updates.items():
        global_update[name] = 1 / args.participant_sample_size * model_updates[name].sum(dim=0, keepdim=True)
    return global_update



def flame(trained_params, current_model_param, param_updates):
    # === clustering ===
    trained_params = torch.stack(trained_params).double()
    cluster = hdbscan.HDBSCAN(metric="cosine", algorithm="generic",
                              min_cluster_size=args.participant_sample_size // 2 + 1,
                              min_samples=1, allow_single_cluster=True)
    cluster.fit(trained_params)
    predict_good = []
    for i, j in enumerate(cluster.labels_):
        if j == 0:
            predict_good.append(i)
    k = len(predict_good)

    # === median clipping ===
    model_updates = trained_params[predict_good] - current_model_param
    local_norms = torch.norm(model_updates, dim=1)
    S_t = torch.median(local_norms)
    scale = S_t / local_norms
    scale = torch.where(scale > 1, torch.ones_like(scale), scale)
    model_updates = model_updates * scale.view(-1, 1)

    # === aggregating ===
    trained_params = current_model_param + model_updates
    trained_params = trained_params.sum(dim=0) / k

    # === noising ===
    delta = 1 / (args.participant_sample_size ** 2)
    epsilon = 10000
    lambda_ = 1 / epsilon * (math.sqrt(2 * math.log((1.25 / delta))))
    sigma = lambda_ * S_t.numpy()
    print(f"sigma: {sigma}; #clean models / clean models: {k} / {predict_good}, median norm: {S_t},")
    trained_params.add_(torch.normal(0, sigma, size=trained_params.size()))

    # === bn ===
    global_update = dict()
    for i, (name, param) in enumerate(param_updates.items()):
        if 'num_batches_tracked' in name:
            global_update[name] = 1 / k * \
                                  param_updates[name][predict_good].sum(dim=0, keepdim=True)
        elif 'running_mean' in name or 'running_var' in name:
            local_norms = torch.norm(param_updates[name][predict_good], dim=1)
            S_t = torch.median(local_norms)
            scale = S_t / local_norms
            scale = torch.where(scale > 1, torch.ones_like(scale), scale)
            global_update[name] = param_updates[name][predict_good] * scale.view(-1, 1)
            global_update[name] = 1 / k * global_update[name].sum(dim=0, keepdim=True)

    return trained_params.float().to(args.device), global_update



def ACORN(model_updates, b, current_round):

    # pdb.set_trace()
    keys = list(model_updates.keys())
    last_layer_updates = model_updates[keys[-2]]
    
    # select
    last_layer_updates = last_layer_updates.float()
    l2_norm = torch.norm(last_layer_updates, dim=1)
    sorted_l2_norm, sorted_indices = torch.sort(l2_norm)
    
    if current_round == 101:
        cnt = last_layer_updates.shape[0]
        b = sorted_l2_norm[int(args.min_threshold * cnt)]
        
    benign_index = torch.searchsorted(sorted_l2_norm, b, right=True).item()
    indices_selected = sorted_indices[:benign_index]
    print(benign_index)
 
    global_update = dict()
    for name in model_updates.keys():
        global_update[name] = model_updates[name][indices_selected].float().mean(dim=0)
    # global_update[keys[-2]] = masked_updates[indices_selected].float().mean(dim=0)

    
    return global_update, b



def aion(model_updates, l2_old, linf_old, linf_shprg_old, b_old, current_round):

    # pdb.set_trace()
    keys = list(model_updates.keys())
    if args.dataset == 'emnist' and args.emnist_style == 'byclass':
        last_layer_updates = model_updates[keys[-1]]
    else:
        last_layer_updates = model_updates[keys[-2]]

    # SHPRG init
    initialization_values_filename = "./FL_Backdoor_CV/shprg/initialization_values"
    m, cnt = last_layer_updates.shape[1], last_layer_updates.shape[0]
    n, _, p, q = load_initialization_values(initialization_values_filename)
    filename = "matrix"+'_'+str(m)
    shprg = SHPRG(n, m, p, q, filename)
    seeds = shprg.generate_seeds(cnt)
    max_mask = args.weight * linf_old
    
    # SHPRG generation
    vector = torch.tensor([shprg.generate(seed, m, max_mask) for seed in seeds]).cuda()
    masked_updates = last_layer_updates + vector
    server_sum_vector = torch.tensor(shprg.client_sum_hprg(seeds, m, max_mask)).cuda()
    linf_norm_shprg = torch.norm(server_sum_vector, p=float('inf')).item()
    
    # select
    l2_norm = torch.norm(masked_updates, dim=1)
    sorted_l2_norm, sorted_indices = torch.sort(l2_norm)
    
    if current_round <= 3 or (args.resume and current_round <= int(re.findall(r'\d+\d*', args.resumed_name.split('/')[1])[0]) + 3):
        b = sorted_l2_norm[int(args.min_threshold * cnt)]
    else:
        b = (l2_old[1] + linf_norm_shprg) / (l2_old[0] + linf_shprg_old) * b_old
    
    benign_index = torch.searchsorted(sorted_l2_norm, b).item()
    benign_index = max(int(args.min_threshold * cnt), min(int(0.8 * cnt), benign_index))
    indices_selected = sorted_indices[:benign_index]

    global_update = dict()
    for name in model_updates.keys():
        global_update[name] = model_updates[name][indices_selected].float().mean(dim=0)
    # global_update[keys[-2]] = masked_updates[indices_selected].float().mean(dim=0)

    # computation for next round
    last_layer_global_update = global_update[keys[-2]]
    l2_norm_global_new = torch.norm(last_layer_global_update).item()
    if current_round <= 2 or (args.resume and current_round <= int(re.findall(r'\d+\d*', args.resumed_name.split('/')[1])[0]) + 2):
        l2_old.append(l2_norm_global_new)
        l2_norm_global = l2_old
    else:
        l2_norm_global = [l2_old[1], l2_norm_global_new]
    linf_norm_global = torch.norm(last_layer_global_update, p=float('inf')).item()
    
    return global_update, l2_norm_global, linf_norm_global, linf_norm_shprg, b, benign_index
