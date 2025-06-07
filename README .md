# Aion

Aion is a multi-round single-mask secure aggregation scheme with evolving input validation against malicious clients and aggregators.
This project demonstrates the performance of Aion's secure aggregation methods and showcases Aion's robustness against poisoning attacks and gradient inversion attacks (GIA).

For further details, please refer to our paper *"Aion: Robust and Efficient Multi-Round Single-Mask Secure Aggregation Against Malicious Participants"*, accepted at USENIX Security'25.

This repository contains three primary components:
1.  **Secure Aggregation (Main Protocol):** Code to run the main protocol of our secure aggregation protocol Aion, as well as other comparative masking-based secure aggregation protocols, including SecAgg, SecAgg+, Flamingo, and ACORN.

2.  **Input Validation Module :** Code to run the input validation module of Aion against poisoning attacks.

3.  **Gradient Inversion Attack (Optional):** Code to implement the GIA on Aion. This is an optional test, as it is implemented in our appendix to evaluate Aion's privacy protection capabilities for client data.


Please follow the environment setup and usage instructions, and note that different components have different dependencies and workflows.

---

## 1. Secure Aggregation (Main Protocol)

This section covers the simulation and comparison of various secure aggregation protocols.

### 1.1 System Requirements

*   Operating System: Linux (e.g., Ubuntu 20.04) or Windows 10/11.
*   Python 3.8 or higher.

### 1.2 Installation Instructions

We recommend using Anaconda to set up the environment.

1.  Create a new Conda environment named `aion` and activate it:
    ```bash
    conda create --name aion python=3.8
    conda activate aion
    ```

2.  Use pip to install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### 1.3 Usage Instructions

#### 1.3.1 **Secure Aggregation (Main Protocol) of Aion**

First enter into folder `pki_files` and run `setup_pki.py`
```bash
cd pki_files
python setup_pki.py
cd ..
```

Our program has multiple configs.

```bash
-c [protocol name] 
-n [number of clients (power of 2)]
-i [number of iterations (training rounds)] 
-A [number of aggregators]   # In masking-based secure aggregation schemes, the aggregators are responsible for collecting and reconstructing the secret shares
```
Aion supports batches of clients with size power of 2,  e.g., 128, 256, 512, 1024, 2048, 4096.

Example command:
```bash
# Run Aion
python abides.py -c aion -n 128 -A 8 -i 10 
```

#### 1.3.2 **Comparison with Other Protocols (Optional)**

We have implemented several protocols for comparison:

1. **SecAgg**
2. **SecAgg+**
3. **Flamingo**

To run different protocols, use the following commands:

```bash
# Run SecAgg
python abides.py -c secagg -n 128 -i 10            # In SecAgg, the number of aggregators (-A) must be equal to the number of clients (-n)

# Run SecAgg+
python abides.py -c secagg_plus -n 128 -A 8 -i 10

# Run Flamingo
python abides.py -c flamingo -n 128 -A 8 -i 10
```

4. **ACORN**

ACORN is another protocol implemented for comparison. To run ACORN, it is needed to install an additional package (only supported on **Linux** (e.g., Ubuntu 20.04)):

```bash
pip install fastecdsa
```

To run ACORN:
```bash
# Run ACORN
python abides.py -c acorn -n 128 -A 8 -i 10
```

---


## 2. Input Validation Module

This section covers Aion's Input Validation module, which is a pluggable component designed to defend against poisoning attacks.​

### 2.1 System Requirements

*   Operating System: Linux (e.g., Ubuntu 20.04) or Windows 10/11.
*   Python 3.11 or higher.

### 2.2 Supported Dataset and Model

- **Datasets**: CIFAR10, FMNIST, EMNIST-Byclass  
- **Models**: LeNet5, ResNet18, ResNet9

### 2.3 Environment Dependencies

#### 2.3.1 Method 1: Deploy with Docker (Recommended)

Using Docker is **highly recommended** as it includes all dependencies and the project code in a pre-configured image.

1. Download the pre-built image:

```bash
docker pull aionaion/input_validation:latest
```

2. Run the main container:

```bash
docker run --gpus all --rm aionaion/input_validation:latest
```

> If GPU is not supported, simply omit `--gpus all`.

#### 2.3.2 Method 2: Deploy without Docker

Create a new Python environment and install dependencies:

```bash
conda create -n aion_iv python=3.11
conda activate aion_iv
pip install torch==2.4.0+cu124 torchvision==0.19.0+cu124 torchaudio==2.4.0+cu124 --index-url https://download.pytorch.org/whl/cu124
pip install -r requirements.txt
```

### 2.4 Usage Instructions

Docker users should enter the container using:

```bash
docker run --gpus all -it aionaion/input_validation:latest /bin/bash
```

#### 2.4.1 Parameters
```bash
--number_of_adversaries     # Number of attackers
--participant_sample_size   # Number of participants each round
--mal_boost                 # Boost rate of malicious gradients
--weight                    # Mask ratio
```

#### 2.4.2 Step-by-Step Evaluation

Train the target models (Optional)

```bash
python ./FL_Backdoor_CV/roles/trainer.py --dataset cifar10 --params utils/cifar10_params.yaml
```

> Models will be stored in `saved_models`. You may change the dataset using `--dataset`.

Execute model replacement attack:

- Varying `poison_ratio` (Figures 4–5 in our paper):

```bash
python ./FL_Backdoor_CV/roles/attack1_cifar10.py --aggregation_rule aion --number_of_adversaries 5
```

- Varying `mask_ratio` (Figures 6–7 in our paper):

```bash
python ./FL_Backdoor_CV/roles/attack2_cifar10.py --aggregation_rule aion --weight 0.1
```

- Varying `boost_rate` (Figures 8–9 in our paper):

```bash
python ./FL_Backdoor_CV/roles/attack3_cifar10.py --aggregation_rule aion --mal_boost 80
```

#### 2.4.3 Free Evaluation

Run with custom parameters:

```bash
python ./FL_Backdoor_CV/roles/trainer.py
```

> Set parameters in `configs.py`. Use `--resumed_name` to load specific checkpoints.

---


## 3. Gradient Inversion Attack (Optional)

This section provides instructions to implement the gradient inversion attack against Aion.

### 3.1 System Requirements

*   Operating System: Linux (e.g., Ubuntu 20.04) or Windows 10/11.
*   Python 3.10 or higher.


### 3.2 Environment Dependencies

#### 3.2.1 Method 1: Deploy with Docker (Recommended)

Using Docker is **highly recommended** as it includes all dependencies and the project code in a pre-configured image.

1. Pull the image from the Docker registry:
    ```bash
    docker pull aionaion/gradattack:latest
    ```

2. Enter the container's interactive environment. The following commands also mount a local `results` directory into the container to save attack outputs.

    *   **On Windows:**
        ```bash
        docker run --rm -it --gpus all -v "%cd%\results:/app/results" aionaion/gradattack /bin/bash
        ```

    *   **On Linux:**
        ```bash
        sudo docker run --rm -it --gpus all -v "$PWD/results":/app/results aionaion/gradattack /bin/bash
        ```
    
    > **Note:** Please create a `results` directory in your current path if it does not exist.

#### 3.2.2 Method 2: Deploy without Docker

1.  Create a new Conda environment named `aion_gia` and activate it:
    ```bash
    conda create -n aion_gia python=3.10
    conda activate aion_gia
    ```

2.  Install PyTorch with CUDA support (example for CUDA 12.1):
    ```bash
    pip install torch==2.2.0+cu121 torchvision==0.17.0+cu121 torchaudio==2.2.0+cu121 -f https://download.pytorch.org/whl/cu121/torch_stable.html
    ```

3.  Install all other dependencies from the `pyproject.toml` file:
    ```bash
    pip install -e .
    ```

### 3.3 Usage Instructions

All of the following commands should be executed from within the activated environment (manual install) or the Docker container's interactive shell (Docker install). The primary files are `train_cifar10.py` and `attack_cifar10_gradinversion.py`.

#### 3.3.1 Train the Target Model (Optional)

This step trains a ResNet18 model. **This is optional**, as we provide pre-trained models in the `checkpoint_old` folder.

To train the model on CIFAR10 for 48 epochs, run:
```bash
python3 examples/train_cifar10.py --scheduler ReduceLROnPlateau --tune_on_val 0.02 --lr 0.05 --lr_factor 0.5 --n_epoch 48 --logname CIFAR10/Aion --defense_aion --weight 0.1
```
The resulting model will be saved in the `checkpoint` folder.

#### 3.3.2 Execute Gradient Inversion Attack

This step runs the GIA against a trained model.

*   To attack our provided pre-trained model:
    ```bash
    python3 examples/attack_cifar10_gradinversion.py --batch_size 16 --BN_exact --tv 0.1 --bn_reg 0.005 --defense_aion --weight 0.1 --attack_checkpoint checkpoint_old/aion_epoch=48.ckpt
    ```

*   To attack a model trained yourself (example):
    ```bash
    python3 examples/attack_cifar10_gradinversion.py --batch_size 16 --BN_exact --tv 0.1 --bn_reg 0.005 --defense_aion --weight 0.1 --attack_checkpoint checkpoint/aion_epoch=48.ckpt
    ```

The reconstructed image, `reconstructed.png`, will be saved in the `results` folder on your local machine (the one you mapped to the Docker container).