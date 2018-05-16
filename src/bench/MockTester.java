package bench;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import crpyto.CryptographicUtils;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import serialization.generated.BVerifyAPIMessageSerialization.Update;
import serialization.generated.MptSerialization.MerklePrefixTrie;
import server.BVerifyServer;

public class MockTester {
	
	private static final Logger logger = Logger.getLogger(MockTester.class.getName());

	// server - for testing.
	private final BVerifyServer server;
	private final PKIDirectory pki;
	
	// the actual mappings (stored so that we can check the server)
	private final Map<ByteBuffer, PerformUpdateRequest> adsIdToLastUpdate;
	private final Map<ByteBuffer, List<Account>> adsIdToOwners;
	
	// commitments 
	private List<byte[]> commitments;
		
	private final List<Entry<byte[], PerformUpdateRequest>> pendingUpdates;
	private int pendingAcceptedCommitments;
	private int lastAcceptedCommitmentNumber;
	private final int batchSize;
	
	// signatures may be omitted (saves time when generating large
	// test cases)
	private final boolean requireSignatures;
	
	private static final int RETRY_PROOF_INTERVAL_MS = 10;
	
	public MockTester(int nClients, int maxClientsPerADS, int nADSes, int batchSize, byte[] startingValue, 
			boolean requireSignatures) {
		logger.log(Level.INFO, "generating mock setup with "+nClients+" clients, "+nADSes+
				" ADSes (max per ADS "+maxClientsPerADS+")"+" batch size: "+batchSize);
		
		// we use concurrent maps, since we want to generate 
		// test data and updates in parallel wherever possible
		this.adsIdToLastUpdate = new ConcurrentHashMap<>();
		this.adsIdToOwners = new ConcurrentHashMap<>();
		
		// start with no commitments 
		this.commitments = new ArrayList<>();
		
		// may or may not need to actually sign
		this.requireSignatures = requireSignatures;
		
		// batching
		this.pendingUpdates = new ArrayList<>();
		this.pendingAcceptedCommitments = 0;
		this.batchSize = batchSize;
						
		List<Account> accounts = PKIDirectory.generateRandomAccounts(nClients);
		
		logger.log(Level.INFO, accounts.size()+" accounts generated");
		List<List<Account>> adsAccounts = getSortedListsOfAccounts(accounts, maxClientsPerADS, 
				nADSes);
		
		// in parallel calculate ADS_IDs and 
		adsAccounts.parallelStream().forEach(x -> {
			byte[] adsId = CryptographicUtils.listOfAccountsToADSId(x);
			for(Account a : x) {
				synchronized(a) {
					a.addADSKey(adsId);
				}
			}
			logger.log(Level.FINE, "{"+x+"} -> "+Utils.byteArrayAsHexString(adsId));
			ByteBuffer adsIdBuffer = ByteBuffer.wrap(adsId);
			
			this.adsIdToOwners.put(adsIdBuffer, x);
			
			// create a request initializing this value
			PerformUpdateRequest initialUpdateRequest = this.createPerformUpdateRequest(
					adsId, startingValue);
			this.adsIdToLastUpdate.put(adsIdBuffer, initialUpdateRequest);	
		});
		
		this.pki = new PKIDirectory(accounts);
		logger.log(Level.INFO, "Number of ADSes: "+this.adsIdToOwners.size());
				
		logger.log(Level.INFO, "Starting the Server");
		this.server = new BVerifyServer(this.pki, this.batchSize, 
				this.adsIdToLastUpdate.values().stream().collect(Collectors.toSet()), requireSignatures);
		
		this.lastAcceptedCommitmentNumber = 0;
		this.waitAndGetNewCommitments();
		
		logger.log(Level.INFO, "Asking for initial proofs");
		boolean initialProofs = this.getAndCheckProofsAllADSIds();
		if(!initialProofs) {
			throw new RuntimeException("not correctly set up");
		}
	}
		
	public void shutdown() {
		this.server.shutdown();
	}
	
	public List<byte[]> getADSIds(){
		return this.adsIdToLastUpdate.keySet().stream().map(x -> x.array()).collect(Collectors.toList());
	}
	
	public boolean requestUpdate(PerformUpdateRequest request) {
		byte[] res = this.server.getRequestHandler().performUpdate(request.toByteArray());
		return parsePerformUpdateResponse(res);
	}
	
	public void addApprovedUpdate(PerformUpdateRequest approvedRequest) {
		// add it to the pending updates
		approvedRequest.getUpdate().getModificationsList().stream().forEach( adsModification -> {
			this.pendingUpdates.add(
					Map.entry(adsModification.getAdsId().toByteArray(), approvedRequest));
		});
		this.pendingAcceptedCommitments++;
		
		// if have a complete batch 
		// we should expect a new commitment
		// with all the accepted updates
		if(this.pendingAcceptedCommitments == this.batchSize) {
			// move all entries to the committed map
			for(Map.Entry<byte[], PerformUpdateRequest> updatesApplied : this.pendingUpdates) {
				this.adsIdToLastUpdate.put(ByteBuffer.wrap(updatesApplied.getKey()), 
						updatesApplied.getValue());
			}
			this.pendingUpdates.clear();
			this.lastAcceptedCommitmentNumber++;
			this.pendingAcceptedCommitments = 0;
			
			// get new commitments;
			this.waitAndGetNewCommitments();
		}
	}
	
	public boolean doUpdate(List<Map.Entry<byte[], byte[]>> adsModifications) {
		PerformUpdateRequest updateRequest = this.createPerformUpdateRequest(adsModifications);
		boolean response  = parsePerformUpdateResponse(
				this.server.getRequestHandler().performUpdate(updateRequest.toByteArray()));
		if(response) {
			this.addApprovedUpdate(updateRequest);
		}
		return response;
	}
	
	public boolean doUpdate(byte[] adsId, byte[] newValue) {
		return this.doUpdate(Arrays.asList(Map.entry(adsId, newValue)));
	}
	
	public boolean getAndCheckProofsAllADSIds() {
		// ask for and check proofs in parallel
		boolean result = this.getADSIds().parallelStream()
				.map(x -> this.getAndCheckProof(x))
				.reduce(Boolean::logicalAnd)
				.get().booleanValue();
		return result;
	}
	
	public boolean getAndCheckProof(byte[] adsId) {
		logger.log(Level.FINE, "asking for proof for ADS ID: "+Utils.byteArrayAsHexString(adsId));
		ProveADSRootRequest request = createProveADSRootRequest(adsId);
		try {
			// request a proof
			ProveADSRootResponse proofResponse = parseProveADSResponse(
					this.server.getRequestHandler().proveADSRoot(request.toByteArray()));
			ADSRootProof proof = proofResponse.getProof();
			// check the proof
			PerformUpdateRequest lastUpdateRequest = this.adsIdToLastUpdate.get(ByteBuffer.wrap(adsId));
			boolean correctProof = this.checkProof(adsId, lastUpdateRequest, proof);
			if(!correctProof) {
				logger.log(Level.WARNING, "proof failed for ADS ID: "+Utils.byteArrayAsHexString(adsId));
				return false;
			}
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		return true;
	}
		
	public ProofSize getProofSize(byte[] adsId) {
		logger.log(Level.FINE, "getting proof size for ADS ID: "+Utils.byteArrayAsHexString(adsId));
		ProveADSRootRequest request = createProveADSRootRequest(adsId);
		try {
			// request a proof
			// and record the length
			byte[] proof = this.server.getRequestHandler().proveADSRoot(request.toByteArray());
			
			int rawProofSize = proof.length;
			ProveADSRootResponse proofResponse = parseProveADSResponse(proof);
			int sizeUpdate = proofResponse.getProof().getLastUpdate().getSerializedSize();
			int sizeUpdateProof = proofResponse.getProof().getLastUpdatedProof().getSerializedSize();
			int sizeFreshnessProof = 0;
			for(MerklePrefixTrie mpt : proofResponse.getProof().getFreshnessProofList()) {
				sizeFreshnessProof+= mpt.getSerializedSize();
			}
			return new ProofSize(rawProofSize, sizeUpdate, sizeUpdateProof, sizeFreshnessProof);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private int getNextCommitmentNumber() {
		return this.commitments.size();
	}
	
	private int getCurrentCommitmentNumber() {
		return this.commitments.size()-1;
	}
	
	private byte[] getCommitment(int commitmentNumber) {
		return this.commitments.get(commitmentNumber);
	}
	
	private void waitAndGetNewCommitments() {
		try {
			// if there are outstanding commitments...
			while(this.lastAcceptedCommitmentNumber != this.getCurrentCommitmentNumber()) {
				List<byte[]> commitments = this.server.getRequestHandler().commitments();
				// if new commitments
				if(commitments.size()-1 != this.getCurrentCommitmentNumber()) {
					for(int i = 0 ; i < commitments.size(); i++) {
						if(i < this.commitments.size()) {
							if(!Arrays.equals(this.commitments.get(i), commitments.get(i))) {
								throw new RuntimeException("bug on server - something wrong");
							}
						}else {
							logger.log(Level.FINE, "new commitment #"+i+": "+Utils.byteArrayAsHexString(commitments.get(i)));
						}
					}
					this.commitments = commitments;
				}else {
					// otherwise sleep to give the server a chance
					// to commit the entries
					Thread.sleep(RETRY_PROOF_INTERVAL_MS);
				}
			}
		} catch (RemoteException | InterruptedException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private boolean checkProof(byte[] adsId, PerformUpdateRequest correctLastUpdateRequest, 
			ADSRootProof proof) {
		byte[] adsValue = null;
		logger.log(Level.FINE, "checking proof for ADS ID: "+Utils.byteArrayAsHexString(adsId));
		// first check the last update is correct 
		logger.log(Level.FINE, "...checking that last update is correct");
		if(!proof.getLastUpdate().equals(correctLastUpdateRequest)) {
			logger.log(Level.WARNING, "last update is not correct got: "+proof.getLastUpdate()+"\nexepcted: "+
					correctLastUpdateRequest);
			return false;
		}
		logger.log(Level.FINE, "...checking that last update was performed");
		// then check that the update was performed 
		Update lastUpdate = correctLastUpdateRequest.getUpdate();
		try {
			MPTDictionaryPartial updateProof = MPTDictionaryPartial.deserialize(proof.getLastUpdatedProof());
			final int updateCommitmentNumber = lastUpdate.getValidAtCommitmentNumber();
			byte[] witnessedUpdateCommitment = this.getCommitment(updateCommitmentNumber);
			byte[] proofUpdateCommitment = updateProof.commitment();
			if(!Arrays.equals(witnessedUpdateCommitment, proofUpdateCommitment)) {
				logger.log(Level.WARNING, "proof update commitment: "+Utils.byteArrayAsHexString(proofUpdateCommitment)+
										"\n witnessed update commitment: "+Utils.byteArrayAsHexString(witnessedUpdateCommitment));
				return false;
			}
			for(ADSModification adsModification : lastUpdate.getModificationsList()) {
				byte[] id = adsModification.getAdsId().toByteArray();
				byte[] value = updateProof.get(adsModification.getAdsId().toByteArray());
				if(!Arrays.equals(value, adsModification.getNewValue().toByteArray())) {
					logger.log(Level.WARNING, "ads modification for last update not applied for: "+
								Utils.byteArrayAsHexString(id));
					return false;
				}
				if(Arrays.equals(adsId, id)) {
					adsValue = value;
				}
			}
			if(adsValue == null) {
				logger.log(Level.WARNING, "no ads value provided for adsid: "+
						Utils.byteArrayAsHexString(adsId));
				return false;
			}
			
			// now check the freshness proof 
			int sizeOfFreshnessProof = this.getCurrentCommitmentNumber()-updateCommitmentNumber;
			if(proof.getFreshnessProofCount() != sizeOfFreshnessProof) {
				logger.log(Level.WARNING, "incomplete freshness proof");
				return false;
			}
			// check freshness proof
			for(int i = 0; i < sizeOfFreshnessProof; i++) {
				int commitmentNumber = updateCommitmentNumber+1+i;
				byte[] witnessedCommitment = this.getCommitment(commitmentNumber);
				updateProof.processUpdates(proof.getFreshnessProof(i));
				byte[] freshnessProofValue = updateProof.get(adsId);
				byte[] freshnessProofCommitment = updateProof.commitment();
				if(!Arrays.equals(adsValue, freshnessProofValue)){
					logger.log(Level.WARNING, "ads value: "+Utils.byteArrayAsHexString(adsValue)+
							"\n freshness proof value: "+Utils.byteArrayAsHexString(freshnessProofValue));
				}
				if(!Arrays.equals(witnessedCommitment, freshnessProofCommitment)) {
					logger.log(Level.WARNING, "witnessed commitment: "+Utils.byteArrayAsHexString(witnessedCommitment)+
							"\n freshness proof commitment: "+Utils.byteArrayAsHexString(freshnessProofCommitment));
					return false;
				}
			}
				
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
			
	public PerformUpdateRequest createPerformUpdateRequest(List<Map.Entry<byte[], byte[]>> adsModifications) {
		Update.Builder update = Update.newBuilder()
				.setValidAtCommitmentNumber(this.getNextCommitmentNumber());
		// if include signatures, need to calculate signers, the witness
		// and actually have each person sign
		if(this.requireSignatures) {
			Set<Account> accounts = new HashSet<>();
			for(Map.Entry<byte[], byte[]> adsModification : adsModifications) {
				ADSModification modification = ADSModification.newBuilder()
						.setAdsId(ByteString.copyFrom(adsModification.getKey()))
						.setNewValue(ByteString.copyFrom(adsModification.getValue()))
						.build();
				update.addModifications(modification);
				accounts.addAll(this.adsIdToOwners.get(ByteBuffer.wrap(adsModification.getKey())));
			}
			PerformUpdateRequest request = calculateAndAddSignatures(update.build(), 
					accounts.stream().collect(Collectors.toList()));
			return request;
		}
		// if no signatures, just leave this blank
		for(Map.Entry<byte[], byte[]> adsModification : adsModifications) {
			ADSModification modification = ADSModification.newBuilder()
					.setAdsId(ByteString.copyFrom(adsModification.getKey()))
					.setNewValue(ByteString.copyFrom(adsModification.getValue()))
					.build();
			update.addModifications(modification);
		}
  		PerformUpdateRequest request = PerformUpdateRequest.newBuilder().setUpdate(update).build();
  		return request;
	}
	
	public PerformUpdateRequest createPerformUpdateRequest(byte[] adsId, byte[] newValue) {
		return createPerformUpdateRequest(Arrays.asList(Map.entry(adsId, newValue)));
	}
			
	public static PerformUpdateRequest calculateAndAddSignatures(Update update, List<Account> accounts) {
		// calculate the witness
		byte[] witness = CryptographicDigest.hash(update.toByteArray());
		Collections.sort(accounts);
  		PerformUpdateRequest.Builder request = PerformUpdateRequest.newBuilder()
				.setUpdate(update);
  		for(Account a : accounts) {
  			byte[] signature = CryptographicSignature.sign(witness, a.getPrivateKey());
  			request.addSignatures(ByteString.copyFrom(signature));
  		}
		return request.build();
	}
	
	public static ProveADSRootRequest createProveADSRootRequest(byte[] adsId) {
		return ProveADSRootRequest.newBuilder().setAdsId(ByteString.copyFrom(adsId)).build();
	}
	
	public static ProveADSRootResponse parseProveADSResponse(byte[] adsRootProof) {
		try {
			ProveADSRootResponse response = ProveADSRootResponse.parseFrom(adsRootProof);
			return response;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());

		}
	}
	
	public static boolean parsePerformUpdateResponse(byte[] response) {
		try {
			return PerformUpdateResponse.parseFrom(response).getAccepted();
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	
	private static List<List<Account>> getSortedListsOfAccounts(List<Account> accounts, 
			int maxClientsPerADS, int nADSes){
		List<List<Account>> res = new ArrayList<>();
		for(int k = 1; k <= maxClientsPerADS; k++) {
			res.addAll(getSortedListsOfAccounts(accounts, k));
			logger.log(Level.INFO, res.size()+" sets of accounts generated so far");
		}
		if(res.size() < nADSes) {
			throw new RuntimeException("insufficient number of accounts");
		}
		return res.subList(0, nADSes);
	}
	
	private static List<List<Account>> getSortedListsOfAccounts(List<Account> accounts, int k){
		return processLargerSubsets(accounts, new ArrayList<>(), k, 0);
	}

	private static List<List<Account>> processLargerSubsets(List<Account> set, List<Account> subset, 
			int targetSize, int nextIndex) {
	    if (targetSize == subset.size()) {
	    	// also sort the subset
	    	Collections.sort(subset);
	    	return Arrays.asList(subset);
	    } else {
	    	List<List<Account>> subsets = new ArrayList<>();
	        for (int j = nextIndex; j < set.size(); j++) {
	        	List<Account> newSubset = new ArrayList<>(subset);
	        	newSubset.add(set.get(j));
	        	subsets.addAll(
	        			processLargerSubsets(set, newSubset, targetSize, j + 1));
	        }
	        return subsets;
	    }
	}
	
	public static void writeBytesToFile(File f, byte[] toWrite) {
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(toWrite);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static byte[] readBytesFromFile(File f) {
		try {
			FileInputStream fis = new FileInputStream(f);
			byte[] data = new byte[(int) f.length()];
			fis.read(data);
			fis.close();
			return data;
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
	}
}
