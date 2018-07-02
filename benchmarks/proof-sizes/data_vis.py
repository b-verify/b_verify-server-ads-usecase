import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os 


data_file = os.path.join(os.path.dirname(os.getcwd()), "proof-sizes/data/proof_size_benchmark.csv")

proof_sizes = pd.read_csv(data_file)
single_ads_update = proof_sizes[proof_sizes['nADSModifiedInLastUpdate'] == 1]
double_ads_update = proof_sizes[proof_sizes['nADSModifiedInLastUpdate'] == 2]
triple_ads_update = proof_sizes[proof_sizes['nADSModifiedInLastUpdate'] == 3]


# This is used to calculate and plot the proof sizes 
# for the warehouse receipt application. This produced
# the plot in Figure 7 in the paper
def plot_proof_sizes():
    x = single_ads_update['nUpdatesSince']
    y_issued = single_ads_update['proofSizeTotal'] 
    y_transfer = double_ads_update['proofSizeTotal'] - double_ads_update['signaturesSize'] + 71*3
    y_loaned = triple_ads_update['proofSizeTotal'] - triple_ads_update['signaturesSize'] + 71*3
    proof_size_issued, = plt.plot(x, y_issued, 'r^', linestyle = '-', label='Issued')
    proof_size_transfer, = plt.plot(x, y_transfer, 'bo', linestyle = '-', label='Transferred')
    proof_size_loaned, = plt.plot(x, y_loaned, 'gs', linestyle = '-', label='Loaned')
    plt.xlabel("Total Modifications to Other Verification Objects Processed")
    plt.ylabel("Size of the Proof in Bytes")  
    plt.title("Proof Sizes For Verification Objects In Application")
    plt.legend(handles=[proof_size_issued, proof_size_transfer, proof_size_loaned], loc=2)
    plt.show()

# This is used to get a breakdown of the proof sizes
# for the warehouse receipt application. This produced
# Table 2 in the paper.
def proof_size_breakdown():
    sizeUpdateTotal = single_ads_update['lastUpdateSize'][0] 
    nSignatures = single_ads_update['nSignatures'][0] 
    sizeSigs = single_ads_update['signaturesSize'][0]
    sizeUpdate = sizeUpdateTotal - sizeSigs
    sizeUpdateProof = single_ads_update['updateProofSize'][0]
    print("-------- verification object for issued receipt ----------")
    print('total: '+str(sizeUpdateTotal))
    print('# sigs: '+str(nSignatures))
    print('size sigs: '+str(sizeSigs))
    print('size update: '+str(sizeUpdate))
    print('size update proof: '+str(sizeUpdateProof))  
    sizeUpdateTotal = double_ads_update['lastUpdateSize'][0] - double_ads_update['signaturesSize'] + 3*71
    nSignatures = 3
    sizeSigs = 3*71
    sizeUpdate = sizeUpdateTotal - sizeSigs
    sizeUpdateProof = double_ads_update['updateProofSize'][0]
    print("-------- verification object for transferred receipt ----------")
    print('total: '+str(sizeUpdateTotal))
    print('# sigs: '+str(nSignatures))
    print('size sigs: '+str(sizeSigs))
    print('size update: '+str(sizeUpdate))
    print('size update proof: '+str(sizeUpdateProof))
    sizeUpdateTotal = triple_ads_update['lastUpdateSize'][0] - triple_ads_update['signaturesSize'] + 3*71
    nSignatures = 3
    sizeSigs = 3*71
    sizeUpdate = sizeUpdateTotal - sizeSigs
    sizeUpdateProof = triple_ads_update['updateProofSize'][0]
    print("-------- verification object for loaned receipt ----------")
    print('total: '+str(sizeUpdateTotal))
    print('# sigs: '+str(nSignatures))
    print('size sigs: '+str(sizeSigs))
    print('size update: '+str(sizeUpdate))
    print('size update proof: '+str(sizeUpdateProof))

def plot_impact_of_optimization():
    x = single_ads_update['nUpdates']
    y_issued = single_ads_update['proofSizeTotal'] 
    y_transfer = double_ads_update['proofSizeTotal'] - double_ads_update['signaturesSize'] + 71*3
    y_loaned = triple_ads_update['proofSizeTotal'] - triple_ads_update['signaturesSize'] + 71*3
    
    
    y_issued_prime = single_ads_update['proofSizeTotal'] - single_ads_update['freshnessProofSize']+single_ads_update['freshnessProofNoOptimizationSize']
    y_transfer_prime = double_ads_update['proofSizeTotal'] - double_ads_update['signaturesSize'] + 71*3 - double_ads_update['freshnessProofSize'] + double_ads_update['freshnessProofNoOptimizationSize']
    y_loaned_prime = triple_ads_update['proofSizeTotal'] - triple_ads_update['signaturesSize'] + 71*3 - triple_ads_update['freshnessProofSize'] + triple_ads_update['freshnessProofNoOptimizationSize']
    
    proof_size_partial_paths_issued, = plt.plot(x, y_issued, 'r^', linestyle='-', label="Issued with Optimization")
    proof_size_partial_paths_transferred, = plt.plot(x, y_transfer, 'bo', linestyle='-', label="Transferred with Optimization")
    proof_size_partial_paths_loaned, = plt.plot(x, y_loaned, 'gs', linestyle='-', label="Loaned with Optimization")

    proof_size_full_paths_issued, = plt.plot(x, y_issued_prime, 'r^', linestyle='--', label="Issued without Optimization")
    proof_size_full_paths_transferred, = plt.plot(x, y_transfer_prime, 'bo', linestyle='--', label="Transferred without Optimization")
    proof_size_full_paths_loaned, = plt.plot(x, y_loaned_prime, 'gs', linestyle='--', label="Loaned without Optimization")
    
    plt.xlabel("Total Modifications to Other Verification Objects Processed")
    plt.ylabel("Size of the Proof in Bytes")  
    plt.title("Impact of Caching Optimization on Proof Sizes")
    plt.legend(handles=[proof_size_partial_paths_issued, proof_size_partial_paths_transferred,
                        proof_size_partial_paths_loaned, proof_size_full_paths_issued, 
                        proof_size_full_paths_transferred, proof_size_full_paths_loaned], loc=2)
    plt.show()