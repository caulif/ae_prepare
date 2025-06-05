# Aion

Aion is a system built for privacy-preserving federated learning, where individual training weights are aggregated using secure aggregation. 

## System Requirements

- Operating System: Linux or Windows
- Python 3.8 or higher
- Anaconda (recommended)

## Installation Instructions

We recommend Anaconda to set up environment.
Create an environment with python 3.8 and then activate it.

```
conda create --name aion python=3.8
conda activate aion
```

Use pip to install required packages.

```
pip install -r requirements.txt
```


## **Secure Aggregation**

First enter into folder `pki_files`, and run
```
cd pki_files
python setup_pki.py
```

Our program has multiple configs.

```
-c [protocol name] 
-n [number of clients (power of 2)]
-i [number of iterations] 
-A [number of aggregators]
```
Aion supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

Example command:
```
python abides.py -c aion -n 128 -A 8 -i 10 
```

## **Comparison with Other Protocols**

We have implemented several protocols for comparison:

1. **SecAgg**
2. **SecAgg+**
3. **Flamingo**

To run different protocols, use the following commands:

```
# Run SecAgg
python abides.py -c secagg -n 128 -i 10 

# Run SecAgg+
python abides.py -c secagg_plus -n 128 -i 10 -A 8

# Run Flamingo
python abides.py -c flamingo -n 128 -i 10 -A 8
```

## **ACORN Protocol**

ACORN is another protocol implemented for comparison. To use ACORN, you need to install an additional package(only supported on Linux and MacOS systems):

```
pip install fastecdsa
```

To run ACORN:
```
python abides.py -c acorn -n 128 -i 10 -A 8
```