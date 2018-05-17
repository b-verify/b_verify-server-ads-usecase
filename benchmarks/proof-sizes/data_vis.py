import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os 


medium_file = os.path.join(os.path.dirname(os.getcwd()), "proof-sizes/data/medium_proof_size_test.csv")

medium_proof_sizes = pd.read_csv(medium_file)

x = (medium_proof_sizes['nUpdates'] / medium_proof_sizes['nADSes'])*100

y_proof_size_total_medium = medium_proof_sizes['proofSizeTotal']

y_update_medium = medium_proof_sizes['updateSize'] + medium_proof_sizes['updateProofSize']

y_freshness_medium = medium_proof_sizes['freshnessProofSize']

proof_size_full_medium, = plt.plot(x, y_proof_size_total_medium, 'b^', linestyle='--', label="Entire Proof")
update_proof_medium, = plt.plot(x, y_update_medium, 'ro', linestyle='--', label="Proof of Update")
freshness_proof_medium, = plt.plot(x, y_freshness_medium, 'gs', linestyle='--', label="Proof of Freshness")


plt.ylabel("Proof Size in Bytes")
plt.xlabel("Percentage of ADSes Updated")
plt.title("Proof Size on b_verify Server with 10^6 ADSes")
plt.suptitle("10% of ADSes Updated in 1% Batches")
plt.legend(handles=[proof_size_full_medium, update_proof_medium, freshness_proof_medium], loc=2)

plt.show()
