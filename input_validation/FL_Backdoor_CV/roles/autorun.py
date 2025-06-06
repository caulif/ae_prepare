import subprocess


aggregation_rules=['aion']
numbers_of_adversaries=[5]

# cifar10
common_command = [
    "python", "./FL_Backdoor_CV/roles/trainer.py",
    "--dataset=cifar10",
    "--params=utils/cifar10_params.yaml",
    "--class_imbalance=0",
    "--balance=0.99",
    "--classes_per_client=2",
    "--resume=1",
    "--resumed_name=cifar10/avg_300.pth",
    "--rounds=1000",
    "--participant_population=500",
    "--participant_sample_size=100",
    "--is_poison=1",
    "--random_compromise=0",
    "--retrain_rounds=60",
    "--poison_prob=0.5",
    "--device=cuda:0",
    "--weight=0.1",
    "--min_threshold=0.1"
]

for aggregation_rule in aggregation_rules:
    for number_of_adversaries in numbers_of_adversaries:
        command = common_command + [f"--number_of_adversaries={number_of_adversaries}"] \
            + [f"--mal_boost={number_of_adversaries * 20}"] + [f"--aggregation_rule={aggregation_rule}"]
        print(f"Executing: {' '.join(command)}")
        subprocess.run(command, check=True)




        
aggregation_rules=['aion']
numbers_of_adversaries=[5]

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
    "--is_poison=1",
    "--random_compromise=0",
    "--retrain_rounds=60",
    "--poison_prob=0.5",
    "--device=cuda:0",
    "--weight=0.1",
    "--min_threshold=0.1"
]

for aggregation_rule in aggregation_rules:
    for number_of_adversaries in numbers_of_adversaries:
        command = common_command + [f"--number_of_adversaries={number_of_adversaries}"] \
            + [f"--mal_boost={number_of_adversaries * 20}"] + [f"--aggregation_rule={aggregation_rule}"]
        print(f"Executing: {' '.join(command)}")
        subprocess.run(command, check=True)





aggregation_rules=['aion']
numbers_of_adversaries=[5]

# emnist_byclass
common_command = [
    "python", "./FL_Backdoor_CV/roles/trainer.py",
    "--dataset=emnist",
    "--emnist_style=byclass",
    "--params=utils/emnist_byclass_params.yaml",
    "--class_imbalance=0",
    "--balance=0.99",
    "--classes_per_client=2",
    "--resume=1",
    "--resumed_name=emnist/avg_100.pth",
    "--rounds=1000",
    "--participant_population=30000",
    "--participant_sample_size=100",
    "--is_poison=1",
    "--random_compromise=0",
    "--retrain_rounds=60",
    "--poison_prob=0.5",
    "--device=cuda:0",
    "--weight=0.1",
    "--min_threshold=0.1"
]

for aggregation_rule in aggregation_rules:
    for number_of_adversaries in numbers_of_adversaries:
        command = common_command + [f"--number_of_adversaries={number_of_adversaries}"] \
            + [f"--mal_boost={number_of_adversaries * 10}"] + [f"--aggregation_rule={aggregation_rule}"]
        print(f"Executing: {' '.join(command)}")
        subprocess.run(command, check=True)