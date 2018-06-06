import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os 


data_file = os.path.join(os.path.dirname(os.getcwd()), "proof-sizes/data/proof_size_benchmark.csv")

proof_sizes = pd.read_csv(data_file)
single_ads_update = proof_sizes[proof_sizes['nSignatures'] == 2]
double_ads_update = proof_sizes[proof_sizes['nSignatures'] == 4]


def plot_proof_sizes():
    x = single_ads_update['nUpdates']
    y_single = single_ads_update['proofSizeTotal']
    y_double = double_ads_update['proofSizeTotal']
    proof_size_single, = plt.plot(x, y_single, 'r^', linestyle = '--', label='Transferred Receipt')
    proof_size_double, = plt.plot(x, y_double, 'bo', linestyle = '--', label='Issued Receipt')
    plt.xlabel("Total Modifications Since ADS Last Upated")
    plt.ylabel("Size of the Proof in Bytes")  
    plt.legend(handles=[proof_size_single, proof_size_double], loc=2)
    plt.show()

def proof_size_breakdown():
    sizeUpdateTotal = single_ads_update['updateSize'][0]
    nSignatures = single_ads_update['nSignatures'][0]
    sizeSigs = single_ads_update['signaturesSize'][0]
    sizeUpdate = sizeUpdateTotal - sizeSigs
    sizeUpdateProof = single_ads_update['updateProofSize'][0]
    print("-------- issued receipt ----------")
    print('total: '+str(sizeUpdateTotal))
    print('# sigs: '+str(nSignatures))
    print('size sigs: '+str(sizeSigs))
    print('size update: '+str(sizeUpdate))
    print('size update proof: '+str(sizeUpdateProof))  
    sizeUpdateTotal = double_ads_update['updateSize'][1]
    nSignatures = double_ads_update['nSignatures'][1]
    sizeSigs = double_ads_update['signaturesSize'][1]
    sizeUpdate = sizeUpdateTotal - sizeSigs
    sizeUpdateProof = double_ads_update['updateProofSize'][1]
    print("-------- transferred receipt ----------")
    print('total: '+str(sizeUpdateTotal))
    print('# sigs: '+str(nSignatures))
    print('size sigs: '+str(sizeSigs))
    print('size update: '+str(sizeUpdate))
    print('size update proof: '+str(sizeUpdateProof))

def plot_impact_of_optimization():
    x = single_ads_update['nUpdates']
    y = single_ads_update['proofSizeTotal']
    y_prime = single_ads_update['proofSizeTotal']-single_ads_update['freshnessProofSize']+single_ads_update['freshnessProofNoOptimizationSize']
    proof_size_partial_paths, = plt.plot(x, y, 'r^', linestyle='--', label="Updates Only")
    proof_size_full_paths, = plt.plot(x, y_prime, 'bo', linestyle='--', label="Full Paths")
    plt.ylabel("Size of the Proof in Bytes")
    plt.xlabel("Total Modifications Since ADS Last Updated")
    plt.title("Impact of Caching Optimization on Proof Sizes")
    plt.legend(handles=[proof_size_partial_paths, proof_size_full_paths], loc=2)
    plt.show()
   

plot_impact_of_optimization() 
