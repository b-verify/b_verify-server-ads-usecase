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

y_freshness_no_optimization_medium = medium_proof_sizes['freshnessProofNoOptimizationSize']

def plot_impact_of_optimization():
    proof_size_full_medium, = plt.plot(x, y_proof_size_total_medium, 'r^', linestyle='--', label="Entire Proof")
    proof_size_full_no_optimization_medium, = plt.plot(x, y_proof_size_total_medium-y_freshness_medium+y_freshness_no_optimization_medium
                                                   , 'bo', linestyle='--', label="Entire Proof Without Caching Optimization")
    plt.ylabel("Proof Size in Bytes")
    plt.xlabel("Percentage of ADSes Updated")
    plt.title("Impact of Caching Optimization on Proof Sizes")
    plt.suptitle("b_verify Server with 10^6 ADSes, 10% of ADSes Updated in 1% Batches")
    plt.legend(handles=[proof_size_full_medium, proof_size_full_no_optimization_medium], loc=2)
    plt.show()
    
def plot_proof_size_breakdown():
    update_proof_medium, = plt.plot(x, y_update_medium, 'rs', linestyle='--', label="Proof of Update")
    freshness_proof_medium, = plt.plot(x, y_freshness_medium, 'g^', linestyle='--', label="Proof of Freshness")
    plt.ylabel("Proof Size in Bytes")
    plt.xlabel("Percentage of ADSes Updated")
    plt.title("Proof Size Breakdown By Component")
    plt.suptitle("b_verify Server with 10^6 ADSes, 10% of ADSes Updated in 1% Batches")
    plt.legend(handles=[update_proof_medium, freshness_proof_medium], loc=2)
    plt.show()        