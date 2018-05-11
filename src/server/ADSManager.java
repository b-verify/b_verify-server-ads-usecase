package server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import bench.BootstrapMockSetup;
import mpt.core.Utils;
import mpt.dictionary.AuthenticatedDictionaryClient;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.Update;
import serialization.generated.MptSerialization.MerklePrefixTrie;

/**
 * This class is responsible for actually managing the 
 * data structures used by the b_verify server and for 
 * creating and storing proofs. 
 * 
 * THREAD SAFETY: 
 * 		getADSRootProof, getCurrentCommitmentNumber are safe 
 * 		for concurrent calls			
 * 
 * 		only one stageUpdate and commit should ever be called
 * 		at once. However stageUpdate can be called 
 * 		concurrently with getADSRootProof, and getCurrentCommitmentNumber
 * 
 * @author henryaspegren
 *
 */
public class ADSManager {
	private static final Logger logger = Logger.getLogger(ADSManager.class.getName());
	
	// for each ADS we store a proof,
	// in the current implementation this stores only the 
	// proof that an update was performed at a given time
	// and the "freshness" proofs are calculated on demand
	// using the saved deltas
	private final Map<String, ADSRootProof> adsRootProofs;
	private final List<MPTDictionaryDelta> deltas;
	
	
	// for efficiency reasons we batch updates
	// updates are added to the authentication tree as they occur
	// but calculation of hash-values and construction of 
	// the full proof is delayed until commit() is called
	private List<PerformUpdateRequest> stagedUpdates;
	private MPTDictionaryFull serverAuthADS;
	
	
	// we store a list of commitments
	// normally these would be witnessed to Bitcoin
	private List<byte[]> commitments;

	// helper information (CONSTANT MAPPINGS)
	// Java NOTE: cannot use byte[] as a key since
	//				implements referential equality so
	//				instead we wrap it with a string
	private final Map<String, Set<Account>> adsIdToOwners;
	private final Map<String, byte[]> adsIdStringToBytes;
	
	public ADSManager(String base, PKIDirectory pki) {
		this.stagedUpdates = new ArrayList<>();
		this.adsRootProofs = new HashMap<>();
		this.deltas = new ArrayList<>();
		this.commitments = new ArrayList<>();
		
		// (1) create a mapping from ADS_ID -> {owners}
		this.adsIdToOwners = new HashMap<>();
		this.adsIdStringToBytes = new HashMap<>();
		Set<Account> accounts = pki.getAllAccounts();
		for(Account a : accounts) {
			Set<byte[]> adsIds = a.getADSKeys();
			for(byte[] adsId : adsIds) {
				// TODO check if other more efficient ways to map 
				//		the id bytes to string 
				String adsIdString = Utils.byteArrayAsHexString(adsId);
				this.adsIdStringToBytes.put(adsIdString, adsId);
				Set<Account> accs = this.adsIdToOwners.get(adsIdString);
				if(accs == null) {
					accs = new HashSet<>();
				}
				accs.add(a);
				this.adsIdToOwners.put(adsIdString, accs);
			}
		}
		logger.log(Level.INFO, "ads_id -> {owners} loaded");
		
		// (2) Second load the MASTER_ADS from disk
		this.serverAuthADS = BootstrapMockSetup.loadServerADS(base);
		logger.log(Level.INFO, "master ads loaded");

		// (3) Create initial update proofs 
		//		for each ADS
		//		NOTE: that the initial values are fixed
		//			  so they just include the 
		//			  full path to the root
		for(Map.Entry<String, byte[]> adsId : this.adsIdStringToBytes.entrySet()) {
			byte[] adsIdByte = adsId.getValue();
			String adsIdString = adsId.getKey();
			AuthenticatedDictionaryClient mptPath = new MPTDictionaryPartial(this.serverAuthADS, adsIdByte);
			MerklePrefixTrie mptPathProof = mptPath.serialize();
			ADSRootProof proof = ADSRootProof.newBuilder()
					.setLastUpdatedProof(mptPathProof)
					.build();
			this.adsRootProofs.put(adsIdString, proof);	
		}
		logger.log(Level.INFO, "initial ads root proofs created");
		
		// (4) Do an initial commitment
		this.commit();
		logger.log(Level.INFO, "added an initial commitment");
		
	}
	
	public Set<Account> getADSOwners(byte[] adsKey){
		String key = Utils.byteArrayAsHexString(adsKey);
		return new HashSet<Account>(this.adsIdToOwners.get(key));
	}
		
	public void stageUpdate(PerformUpdateRequest approvedUpdate) {
		Update update = approvedUpdate.getUpdate();
		// make the changes to the ADS data structure, but defer creating the 
		// proof and comitting (to batch updates)
		for(ADSModification modification : update.getModificationsList()) {
			byte[] adsId = modification.getAdsId().toByteArray();
			byte[] newRoot = modification.getNewValue().toByteArray();
			// store the proof
			this.serverAuthADS.insert(adsId, newRoot);
		}
		this.stagedUpdates.add(approvedUpdate);
	}
	
	public byte[] commit() {
		
		// save delta and clear any changes
		MPTDictionaryDelta delta = new MPTDictionaryDelta(this.serverAuthADS);
		this.deltas.add(delta);
		this.serverAuthADS.reset();
		
		// calculate a new commitment
		byte[] commitment = this.serverAuthADS.commitment();
		this.commitments.add(commitment);

		// create the proofs:
		// go through each update and 
		// create and save a proof 
		// for all ADS_IDs that have changed
		logger.log(Level.FINE, "generating the proofs");
		for(PerformUpdateRequest approvedUpdate : this.stagedUpdates) {
			Update update = approvedUpdate.getUpdate();
			List<byte[]> adsIds = update.getModificationsList().stream()
					.map(x -> x.getAdsId().toByteArray())
					.collect(Collectors.toList());
			MPTDictionaryPartial paths = new MPTDictionaryPartial(this.serverAuthADS, adsIds);
			MerklePrefixTrie updatePerformedProof = paths.serialize();
			ADSRootProof proof = ADSRootProof.newBuilder()
					.setLastUpdate(approvedUpdate)
					.setLastUpdatedProof(updatePerformedProof)
					.build();
			for(byte[] adsId : adsIds) {
				String adsIdString = Utils.byteArrayAsHexString(adsId);
				this.adsRootProofs.put(adsIdString, proof);
			}
		}
		
		logger.log(Level.INFO, "commitment added: "+Utils.byteArrayAsHexString(commitment));
		return commitment;
	}
	
	public ADSRootProof getADSRootProof(byte[] adsId) {
		String adsIdString = Utils.byteArrayAsHexString(adsId);
		// this copies the base proof from the map 
		ADSRootProof.Builder proof = this.adsRootProofs.get(adsIdString).toBuilder();
		int updateAtCommitmentNumber = proof.getLastUpdate().getUpdate().getValidAtCommitmentNumber();
		int currentCommitmentNumber = this.getCurrentCommitmentNumber();
		// add the update proofs
		// TODO: could possibly cache the updated proof!
		for(int commitment = updateAtCommitmentNumber+1; 
				commitment <= currentCommitmentNumber; commitment++) {
			MerklePrefixTrie updates = this.deltas.get(commitment).getUpdates(adsId);
			proof.addFreshnessProof(updates);
		}
		return proof.build();
	}
	
	public int getCurrentCommitmentNumber() {
		return this.commitments.size()-1;
	}
	
}
