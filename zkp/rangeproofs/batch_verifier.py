
# batch_verifier.py

import random
import time
from typing import List, Dict, Any

# Assuming the necessary classes and curve are importable
# Make sure these paths are correct relative to where you run this script
try:
    from zkp.rangeproofs.rangeproof_aggreg_verifier import AggregRangeVerifier, Proof
    from zkp.innerproduct.inner_product_verifier import Verifier1 as InnerProductVerifier # For type hint maybe
    from zkp.utils.utils import ModP, Point
    from zkp.utils.transcript import Transcript # Potentially needed if challenges aren't pre-extracted
    from zkp.pippenger import PipSECP256k1 # Assuming this provides fast multiexponentiation
    from fastecdsa.curve import secp256k1
except ImportError as e:
    print(f"Import Error: {e}")
    print("Please ensure the 'zkp' directory is in your Python path or install the package.")
    exit(1)

CURVE = secp256k1
P_ORDER = CURVE.q # The order of the curve's base point field
IDENTITY = Point(None, None, CURVE) # Elliptic curve identity point


class BatchRangeVerifier:
    """
    Performs batch verification for multiple Aggregated Range Proofs.

    This class utilizes random linear combinations to verify multiple proofs
    more efficiently than individual verification, primarily by reducing the
    number of expensive multiexponentiation operations.

    Note: Batch verification for the inner product proof part is complex and
          currently **not implemented** in this version. This class assumes the
          inner product proofs are valid for the timing comparison of the main
          verification equation.
    """
    def __init__(self):
        """Initializes the BatchRangeVerifier."""
        # No specific state needed for now, but could hold common params
        pass

    def _recalculate_P(self, x: ModP, y: ModP, z: ModP, A: Point, S: Point,
                       gs: List[Point], hs: List[Point], n: int, m: int) -> Point:
        """
        Recalculates the P point based on the logic in AggregRangeVerifier._getP.
        Helper function needed as we don't modify the original class.
        Note: hs passed here should already be the modified h' (hsp).
        """
        nm = n * m
        if len(gs) != nm or len(hs) != nm:
            raise ValueError(f"Length mismatch: len(gs)={len(gs)}, len(hs)={len(hs)}, expected {nm}")

        gs_exponents = [-z for _ in range(nm)]
        hs_exponents = [
            (z * (y ** i)) + (z ** (2 + (i // n))) * (2 ** (i % n))
            for i in range(nm)
        ]
        multiexp_part = PipSECP256k1.multiexp(gs + hs, gs_exponents + hs_exponents)
        P = PipSECP256k1.multiexp([A, S, multiexp_part], [ModP(1, P_ORDER), x, ModP(1, P_ORDER)])
        return P

    def _batch_verify_inner_product(self, inner_product_inputs: List[Dict[str, Any]]) -> bool:
        """
        Placeholder for batch verifying inner product proofs.

        Args:
            inner_product_inputs: A list of dictionaries, each containing the
                                  necessary inputs ('gs', 'hs', 'u', 'commitment',
                                  't_hat', 'inner_proof', 'weight') for verifying
                                  one inner product proof instance within the batch.

        Returns:
            bool: Currently always returns True as a placeholder. A full
                  implementation would perform the actual batch verification.
        """
        print("WARNING: Inner product batch verification is NOT IMPLEMENTED. Assuming valid.")
        if not inner_product_inputs:
             return True # No inner proofs to verify

        # --- Actual Implementation Would Go Here ---
        # This would involve:
        # 1. Recursively applying random linear combinations to the challenges
        #    and commitments generated during the inner product proof protocol's rounds.
        # 2. Performing a final combined multi-exponentiation check.
        # It's significantly more complex than batching the outer layer.
        # For now, we just simulate success.
        # -----------------------------------------
        return True

    def batch_verify(self, verifications_data: List[Dict[str, Any]]) -> bool:
        """
        Performs batch verification for multiple Aggregated Range Proofs.

        Args:
            verifications_data: A list of dictionaries. Each dictionary must contain:
                'Vs': List[Point] - The commitments being verified (V vectors).
                'g': Point - Generator g.
                'h': Point - Generator h.
                'gs': List[Point] - Generator vector gs.
                'hs': List[Point] - Generator vector hs.
                'u': Point - Generator u (for inner product proof).
                'proof': Proof - The Proof object from rangeproof_aggreg_verifier.

        Returns:
            bool: True if all proofs are valid (with high probability), False otherwise.
        """
        num_proofs = len(verifications_data)
        if num_proofs == 0:
            print("Batch Verifier: No proofs provided.")
            return True

        print(f"Batch Verifier: Starting verification for {num_proofs} proofs...")
        start_time = time.time()

        # --- 1. Transcript Verification and Challenge Extraction ---
        precomputed = []
        # print("Batch Verifier: Step 1: Verifying transcripts and extracting challenges...")
        transcript_time = time.time()
        for i, data in enumerate(verifications_data):
            proof = data['proof']
            Vs = data['Vs']
            g = data['g']
            h = data['h']
            gs = data['gs']
            hs = data['hs']
            u = data['u']

            try:
                temp_verifier = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
                temp_verifier.verify_transcript() # Sets temp_verifier.x, y, z
                x = temp_verifier.x
                y = temp_verifier.y
                z = temp_verifier.z
            except Exception as e:
                print(f"Batch Verifier: Transcript verification failed for proof index {i}: {e}")
                return False

            nm = len(gs)
            m = len(Vs)
            if nm == 0 or m == 0 or nm % m != 0:
                print(f"Batch Verifier: Invalid generator/commitment dimensions for proof {i} (nm={nm}, m={m}).")
                return False
            n = nm // m
            h_prime = [(y.inv() ** k) * hs[k] for k in range(nm)]

            precomputed.append({
                'Vs': Vs, 'g': g, 'h': h, 'gs': gs, 'hs': hs, 'h_prime': h_prime, 'u': u,
                'proof': proof, 'x': x, 'y': y, 'z': z, 'n': n, 'm': m
            })
        # print(f"Batch Verifier: Transcript verification took {time.time() - transcript_time:.4f} seconds.")

        # --- 2. Generate Random Weights ---
        zs = [ModP(random.randint(1, P_ORDER - 1), P_ORDER) for _ in range(num_proofs)]

        # --- 3. Combine Main Verification Equations ---
        # print("Batch Verifier: Step 3: Combining main verification equations...")
        combine_time = time.time()
        all_bases = []
        all_exponents = []
        sum_that_z = ModP(0, P_ORDER)
        sum_taux_z = ModP(0, P_ORDER)

        # Terms from LHS: g^(∑ proof_i.t_hat * z_i) * h^(∑ proof_i.taux * z_i)
        for i in range(num_proofs):
            proof = precomputed[i]['proof']
            sum_that_z += proof.t_hat * zs[i]
            sum_taux_z += proof.taux * zs[i]
        if sum_that_z.x != 0:
            all_bases.append(precomputed[0]['g'])
            all_exponents.append(sum_that_z)
        if sum_taux_z.x != 0:
            all_bases.append(precomputed[0]['h'])
            all_exponents.append(sum_taux_z)

        # Terms from RHS_Inv: ∏ RHS_i ^ (-z_i)
        for i in range(num_proofs):
            data = precomputed[i]
            weight = -zs[i]
            Vs, g, proof, x, y, z, n, m, nm = data['Vs'], data['g'], data['proof'], data['x'], data['y'], data['z'], data['n'], data['m'], data['n'] * data['m']

            all_bases.extend(Vs)
            all_exponents.extend([weight * (z ** (j + 2)) for j in range(m)])

            delta_yz = (z - z ** 2) * sum([y ** k for k in range(nm)], ModP(0, P_ORDER)) - \
                       sum([(z ** (j + 2)) * ModP((1 << n) - 1, P_ORDER) for j in range(m)])
            all_bases.append(g)
            all_exponents.append(weight * delta_yz)

            all_bases.append(proof.T1)
            all_exponents.append(weight * x)
            all_bases.append(proof.T2)
            all_exponents.append(weight * (x ** 2))

        # --- 4. Perform the Single Large Multiexponentiation ---
        # print(f"Batch Verifier: Combining equations took {time.time() - combine_time:.4f} seconds.")
        # print(f"Batch Verifier: Step 4: Performing large multiexponentiation with {len(all_bases)} bases...")
        multiexp_time = time.time()
        try:
            filtered_bases = []
            filtered_exponents = []
            for b, e in zip(all_bases, all_exponents):
                if isinstance(e, ModP) and e.x != 0:
                    filtered_bases.append(b)
                    filtered_exponents.append(e)
                # Handle potential non-ModP zero if needed, though likely unnecessary here
            final_check_point = PipSECP256k1.multiexp(filtered_bases, filtered_exponents) if filtered_bases else IDENTITY
        except Exception as e:
            print(f"Batch Verifier: Multiexponentiation failed: {e}")
            return False
        # print(f"Batch Verifier: Multiexponentiation took {time.time() - multiexp_time:.4f} seconds.")

        # --- 5. Check the Result of the Main Equation Batch ---
        main_proofs_valid = (final_check_point == IDENTITY)
        if not main_proofs_valid:
            print("Batch Verifier: Combined main equation check failed.")
            return False
        # print("Batch Verifier: Combined main equation check successful.")

        # --- 6. Prepare Inputs for Inner Product Batch Verification ---
        # print("Batch Verifier: Step 6: Preparing inputs for inner product batch verification...")
        inner_product_inputs = []
        for i in range(num_proofs):
            data = precomputed[i]
            proof, gs, h_prime, h, u, x, y, z, n, m = (
                data['proof'], data['gs'], data['h_prime'], data['h'], data['u'],
                data['x'], data['y'], data['z'], data['n'], data['m']
            )
            P = self._recalculate_P(x, y, z, proof.A, proof.S, gs, h_prime, n, m)
            commitment_point = PipSECP256k1.multiexp([P, h], [ModP(1,P_ORDER), -proof.mu])
            inner_product_inputs.append({
                'gs': gs, 'hs': h_prime, 'u': u, 'commitment': commitment_point,
                't_hat': proof.t_hat, 'inner_proof': proof.innerProof, 'weight': zs[i]
            })

        # --- 7. Call Batch Inner Product Verifier ---
        inner_proofs_valid = self._batch_verify_inner_product(inner_product_inputs)
        if not inner_proofs_valid:
            print("Batch Verifier: Inner product batch verification failed (Placeholder returned False).")
            # In a real implementation, this would indicate failure.
            return False

        total_time = time.time() - start_time
        # print(f"Batch Verifier: Finished in {total_time:.4f} seconds.")
        return True # If both main and inner (placeholder) checks pass