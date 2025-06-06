import subprocess
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from configs import args

# fmnist
common_command = [
    "python", "./FL_Backdoor_CV/roles/trainer.py",
    "--dataset=fmnist",
    "--params=utils/fmnist_params.yaml",
    "--class_imbalance=0",
    "--balance=0.99",
    "--classes_per_client=2",
    "--resume=1",
    "--resumed_name=fmnist/avg_300.pth",
    "--rounds=1000",
    "--participant_population=500",
    "--participant_sample_size=100",
    "--number_of_adversaries=20",
    "--is_poison=1",
    "--random_compromise=0",
    "--retrain_rounds=60",
    "--poison_prob=0.5",
    "--device=cuda:0",
    "--min_threshold=0.1",
    "--weight=0.1"
]

command = common_command + [f"--mal_boost={args.mal_boost}"] + [f"--aggregation_rule={args.aggregation_rule}"]
print(f"Executing: {' '.join(command)}")
subprocess.run(command, check=True)