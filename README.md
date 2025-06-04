# Aion

Aion is a system built for privacy-preserving federated learning, where individual training weights are aggregated using secure aggregation. 


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
python setup_pki.py
```

Our program has multiple configs.

```
-c [protocol name] 
-n [number of clients (power of 2)]
-i [number of iterations] 
```
Aion supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

Example command:
```
python abides.py -c Aion -n 128 -i 10
```

## **Comparison with Other Protocols**

We have implemented several protocols for comparison:

1. **SecAgg**: 
2. **SecAgg+**: 
3. **Flamingo**: 
4. **Acorn**: 

To run different protocols, use the following commands:

```
# Run SecAgg
python abides.py -c secagg -n 128 -i 10

# Run SecAgg+
python abides.py -c secagg_plus -n 128 -i 10

# Run Flamingo
python abides.py -c flamingo -n 128 -i 10

# Run Acorn 
python abides.py -c acorn -n 128 -i 10
```






