import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os 


small_file = os.path.join(os.path.dirname(os.getcwd()), "proof-sizes/data/small_proof_size_test.csv")
medium_file = os.path.join(os.path.dirname(os.getcwd()), "proof-sizes/data/medium_proof_size_test.csv")

small_proof_sizes = pd.read_csv(small_file)
medium_proof_sizes = pd.read_csv(medium_file)

x = (small_proof_sizes['nUpdates'] / small_proof_sizes['nADSes'])*100

y_proof_size_total_small = small_proof_sizes['proofSizeTotal']
y_proof_size_total_medium = medium_proof_sizes['proofSizeTotal']

y_update_small = small_proof_sizes['updateSize'] + small_proof_sizes['updateProofSize']
y_update_medium = medium_proof_sizes['updateSize'] + medium_proof_sizes['updateProofSize']

y_freshness_small_ = small_proof_sizes['freshnessProofSize']
y_freshness_medium = medium_proof_sizes['freshnessProofSize']

proof_size_full_small, = plt.plot(x, y_proof_size_total_small, 'r^', linestyle='--', label="Entire Proof")
update_proof_small, = plt.plot(x, y_update_small, 'ro', linestyle='--', label="Proof of Update")
freshness_proof_small, = plt.plot(x, y_freshness_small_, 'rs', linestyle='--', label="Proof of Freshness")

proof_size_full_medium, = plt.plot(x, y_proof_size_total_medium, 'b^', linestyle='--', label="Entire Proof")
update_proof_medium, = plt.plot(x, y_update_medium, 'bo', linestyle='--', label="Proof of Update")
freshness_proof_medium, = plt.plot(x, y_freshness_medium, 'bs', linestyle='--', label="Proof of Freshness")


plt.ylabel("Proof Size in Bytes")
plt.xlabel("Number of Batched Updates")
plt.title("Proof Size with 10% of ADSes Updates Done in 1% Batches")
plt.legend(handles=[proof_size_full_small, update_proof_small, freshness_proof_small], loc=4)

plt.show()
