# test_batch_verification.py

import time
import random
import sys
import os
from typing import List, Dict, Any

# Adjust path to import zkp modules and the new batch verifier
script_dir = os.path.dirname(os.path.abspath(__file__))
# Assuming zkp package is one level up
zkp_path = os.path.abspath(os.path.join(script_dir, '..'))
if zkp_path not in sys.path:
    sys.path.append(zkp_path)
# Assuming batch_verifier.py is in the same directory as this test script
if script_dir not in sys.path:
     sys.path.append(script_dir)


try:
    from zkp.rangeproofs.rangeproof_aggreg_prover import AggregNIRangeProver
    from zkp.rangeproofs.rangeproof_aggreg_verifier import AggregRangeVerifier, Proof
    from zkp.utils.utils import ModP, Point
    from zkp.utils.commitments import commitment
    from zkp.utils.elliptic_curve_hash import elliptic_hash
    from fastecdsa.curve import secp256k1
    # Import the new batch verifier class
    from batch_verifier import BatchRangeVerifier
except ImportError as e:
    print(f"Import Error: {e}")
    print("Please ensure the 'zkp' directory and batch_verifier.py are accessible.")
    exit(1)


CURVE = secp256k1
P_ORDER = CURVE.q

# --- Configuration ---
NUM_PROOFS = 100     # Number of proofs to generate and verify
N_BITS = 32          # Bit length for the range proof (e.g., 32 for uint32)
MAX_VALUE = (1 << N_BITS) - 1

# --- Generate Common Parameters ---
print("Generating common parameters...")
SEED_G = b'fixed_seed_2'
SEED_H = b'fixed_seed_3'
SEED_GS = b'fixed_seed_0'
SEED_HS = b'fixed_seed_1'
SEED_U = b'fixed_seed_4'
SEED_GAMMA = b'fixed_seed_5' # Seed for gamma in prover if needed

g = elliptic_hash(SEED_G, CURVE)
h = elliptic_hash(SEED_H, CURVE)
u = elliptic_hash(SEED_U, CURVE)
# Generate enough generators for N_BITS
gs = [elliptic_hash(str(i).encode() + SEED_GS, CURVE) for i in range(N_BITS)]
hs = [elliptic_hash(str(i).encode() + SEED_HS, CURVE) for i in range(N_BITS)]
print(f"Generated {N_BITS} gs and hs generators.")

# --- Generate Proofs ---
print(f"\nGenerating {NUM_PROOFS} valid range proofs for n={N_BITS} bits...")
verifications_data: List[Dict[str, Any]] = []
generation_start_time = time.perf_counter()

for i in range(NUM_PROOFS):
    v = ModP(random.randint(0, MAX_VALUE), P_ORDER) # Value within range
    gamma = ModP(random.randint(1, P_ORDER - 1), P_ORDER) # Random blinding factor
    V = commitment(g, h, v, gamma) # Commitment V = g^v * h^gamma

    prover = AggregNIRangeProver(
        vs=[v],        # Proving for a single value, m=1
        n=N_BITS,
        g=g,
        h=h,
        gs=gs,         # Pass all generated gs for N_BITS
        hs=hs,         # Pass all generated hs for N_BITS
        gammas=[gamma],
        u=u,
        group=CURVE,
        seed=f"test_proof_seed_{i}".encode() # Unique seed per proof
    )
    try:
        proof = prover.prove()
        verifications_data.append({
            'Vs': [V], # Vs is a list containing the single commitment V
            'g': g,
            'h': h,
            'gs': gs, # Use the gs matching N_BITS
            'hs': hs, # Use the hs matching N_BITS
            'u': u,
            'proof': proof,
            'client_id': f'client_{i}' # Optional: Add identifier
        })
    except Exception as e:
        print(f"ERROR: Failed to generate proof {i}: {e}")
        # Decide if the test should stop or continue without this proof
        continue # Skip this proof

generation_duration = time.perf_counter() - generation_start_time
print(f"Generated {len(verifications_data)} proofs in {generation_duration:.4f} seconds.")

if not verifications_data:
    print("No proofs were generated successfully. Exiting test.")
    exit()

# --- Individual Verification ---
print(f"\nStarting individual verification for {len(verifications_data)} proofs...")
individual_start_time = time.perf_counter()
individual_success_count = 0
all_individual_valid = True

for i, data in enumerate(verifications_data):
    verifier = AggregRangeVerifier(data['Vs'], data['g'], data['h'], data['gs'], data['hs'], data['u'], data['proof'])
    try:
        is_valid = verifier.verify() # verify() checks both main equation and inner product
        if not is_valid:
            print(f"Individual verification FAILED for proof {i} (client: {data.get('client_id', 'N/A')})")
            all_individual_valid = False
        else:
            individual_success_count += 1
    except Exception as e:
        print(f"Individual verification FAILED for proof {i} (client: {data.get('client_id', 'N/A')}) with error: {e}")
        all_individual_valid = False

individual_duration = time.perf_counter() - individual_start_time
print(f"Individual verification finished in {individual_duration:.4f} seconds.")
print(f"Result: {individual_success_count}/{len(verifications_data)} proofs verified successfully.")
if not all_individual_valid:
    print("ERROR: One or more individual verifications failed.")

# --- Batch Verification ---
print(f"\nStarting batch verification for {len(verifications_data)} proofs...")
batch_verifier = BatchRangeVerifier() # Instantiate the batch verifier
batch_start_time = time.perf_counter()
batch_verification_valid = False
try:
    batch_verification_valid = batch_verifier.batch_verify(verifications_data)
except Exception as e:
    print(f"Batch verification FAILED with error: {e}")
    batch_verification_valid = False

batch_duration = time.perf_counter() - batch_start_time
print(f"Batch verification finished in {batch_duration:.4f} seconds.")
print(f"Result: {'Successful' if batch_verification_valid else 'FAILED'}")


# --- Comparison ---
print("\n--- Timing Comparison ---")
print(f"Number of proofs: {len(verifications_data)}")
print(f"Total time for individual verification: {individual_duration:.4f} seconds")
print(f"Total time for batch verification:      {batch_duration:.4f} seconds")

if batch_duration > 0 and individual_duration > 0:
    speedup = individual_duration / batch_duration
    print(f"Batch verification speedup: {speedup:.2f}x")
else:
    print("Could not calculate speedup factor (zero duration).")

# Final consistency check
if all_individual_valid != batch_verification_valid:
     print("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
     print("ERROR: Mismatch between individual and batch verification results!")
     print(f"Individual result: {all_individual_valid}, Batch result: {batch_verification_valid}")
     print("This indicates a potential bug in the batch verification logic (excluding inner proof part).")
     print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")