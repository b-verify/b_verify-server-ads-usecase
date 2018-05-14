package bench;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
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
import server.BVerifyServer;

public class MockTester {
	private static final Logger logger = Logger.getLogger(MockTester.class.getName());

	// server - for testing.
	private final BVerifyServer server;
	
	// the actual mappings (stored so that we can check the server)
	private final Map<ByteBuffer, PerformUpdateRequest> adsIdToLastUpdate;
	private final Map<ByteBuffer, List<Account>> adsIdToOwners;
	
	// commitments 
	private List<byte[]> commitments;
		
	private final List<Entry<byte[], PerformUpdateRequest>> pendingUpdates;
	private int pendingAcceptedCommitments;
	private int lastAcceptedCommitmentNumber;
	private final int batchSize;
	
	private static final int RETRY_PROOF_INTERVAL_MS = 10;
	
	public MockTester(int nClients, int maxClientsPerADS, int batchSize, byte[] startingValue) {
		this.adsIdToLastUpdate = new HashMap<>();
		this.adsIdToOwners = new HashMap<>();
		this.commitments = new ArrayList<>();
		
		// batching
		this.pendingUpdates = new ArrayList<>();
		this.pendingAcceptedCommitments = 0;
		this.batchSize = batchSize;
						
		List<Account> accounts = PKIDirectory.generateRandomAccounts(nClients);
		int max = (int) Math.pow(2, nClients);
		logger.log(Level.INFO, "generating mock setup with : "+nClients);
		for(int i = 1; i < max; i++) {
			List<Account> adsAccounts = getSortedListOfAccounts(i, maxClientsPerADS, accounts);
			if(adsAccounts == null) {
				continue;
			}
			byte[] adsId = CryptographicUtils.listOfAccountsToADSId(adsAccounts);
			for(Account a : adsAccounts) {
				a.addADSKey(adsId);
			}
			logger.log(Level.FINE, "{"+adsAccounts+"} -> "+Utils.byteArrayAsHexString(adsId));
			ByteBuffer adsIdBuffer = ByteBuffer.wrap(adsId);
			
			this.adsIdToOwners.put(adsIdBuffer, adsAccounts);
			
			// create a request initializing this value
			PerformUpdateRequest initialUpdateRequest = this.createPerformUpdateRequest(adsId, startingValue, 
					this.getNextCommitmentNumber());
			this.adsIdToLastUpdate.put(adsIdBuffer, initialUpdateRequest);			
		}
		PKIDirectory pki = new PKIDirectory(accounts);
		logger.log(Level.INFO, "Number of ADSes: "+this.adsIdToOwners.size());
				
		logger.log(Level.INFO, "Starting the Server");
		this.server = new BVerifyServer(pki, this.batchSize, 
				adsIdToLastUpdate.values().stream().collect(Collectors.toSet()));
		
		this.lastAcceptedCommitmentNumber = 0;
		this.waitAndGetNewCommitments();
		
		logger.log(Level.INFO, "Asking for initial proofs");
		boolean initialProofs = this.getAndCheckProofs();
		if(!initialProofs) {
			throw new RuntimeException("not correctly set up");
		}
	}
	
	public List<byte[]> getADSIds(){
		return this.adsIdToLastUpdate.keySet().stream().map(x -> x.array()).collect(Collectors.toList());
	}
	
	public boolean doUpdate(List<Map.Entry<byte[], byte[]>> adsModifications) {
		PerformUpdateRequest updateRequest = this.createPerformUpdateRequest(adsModifications, this.getNextCommitmentNumber());
		boolean response  = parsePerformUpdateResponse(
				this.server.getRequestHandler().performUpdate(updateRequest.toByteArray()));
		if(response) {
			// add it to the pending updates
			for(Map.Entry<byte[], byte[]> adsModification : adsModifications) {
				this.pendingUpdates.add(Map.entry(adsModification.getKey(), updateRequest));
			}
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
		return response;
	}
	
	public boolean doUpdate(byte[] adsId, byte[] newValue) {
		return this.doUpdate(Arrays.asList(Map.entry(adsId, newValue)));
	}
	
	public boolean getAndCheckProofs() {
		// get a proof for each ADS_ID
		for(byte[] adsId : this.getADSIds()) {
			logger.log(Level.FINE, "asking for proof for ADS ID: "+Utils.byteArrayAsHexString(adsId));
			ProveADSRootRequest request = this.createProveADSRootRequest(adsId);
			try {
				// request a proof
				ProveADSRootResponse proofResponse = parseProveADSResponse(
						this.server.getRequestHandler().proveADSRoot(request.toByteArray()));
				ADSRootProof proof = proofResponse.getProof();
				// check the proof
				PerformUpdateRequest lastUpdateRequest = this.adsIdToLastUpdate.get(ByteBuffer.wrap(adsId));
				boolean correctProof = this.checkProof(adsId, lastUpdateRequest, proof);
				if(!correctProof) {
					logger.log(Level.INFO, "proof failed for ADS ID: "+Utils.byteArrayAsHexString(adsId));
					return false;
				}
			} catch (RemoteException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
		}
		return true;
	}
	
	public List<Integer> getProofSizes(){
		List<Integer> sizes = new ArrayList<>();
		for(byte[] adsId : this.getADSIds()) {
			logger.log(Level.FINE, "asking for proof for ADS ID: "+Utils.byteArrayAsHexString(adsId));
			ProveADSRootRequest request = this.createProveADSRootRequest(adsId);
			try {
				// request a proof
				// and record the length
				byte[] proof = this.server.getRequestHandler().proveADSRoot(request.toByteArray());
				sizes.add(proof.length);
			} catch (RemoteException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
		}
		return sizes;
	}
	
	public int getProofSize(byte[] adsId) {
		ProveADSRootRequest request = this.createProveADSRootRequest(adsId);
		try {
			// request a proof
			// and record the length
			byte[] proof = this.server.getRequestHandler().proveADSRoot(request.toByteArray());
			return proof.length;
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
				logger.log(Level.INFO, "proof update commitment: "+Utils.byteArrayAsHexString(proofUpdateCommitment)+
										"\n witnessed update commitment: "+Utils.byteArrayAsHexString(witnessedUpdateCommitment));
				return false;
			}
			for(ADSModification adsModification : lastUpdate.getModificationsList()) {
				byte[] id = adsModification.getAdsId().toByteArray();
				byte[] value = updateProof.get(adsModification.getAdsId().toByteArray());
				if(!Arrays.equals(value, adsModification.getNewValue().toByteArray())) {
					logger.log(Level.INFO, "ads modification for last update not applied for: "+
								Utils.byteArrayAsHexString(id));
					return false;
				}
				if(Arrays.equals(adsId, id)) {
					adsValue = value;
				}
			}
			if(adsValue == null) {
				logger.log(Level.INFO, "no ads value provided for adsid: "+
						Utils.byteArrayAsHexString(adsId));
				return false;
			}
			
			// now check the freshness proof 
			int sizeOfFreshnessProof = this.getCurrentCommitmentNumber()-updateCommitmentNumber;
			if(proof.getFreshnessProofCount() != sizeOfFreshnessProof) {
				logger.log(Level.INFO, "incomplete freshness proof");
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
					logger.log(Level.INFO, "ads value: "+Utils.byteArrayAsHexString(adsValue)+
							"\n freshness proof value: "+Utils.byteArrayAsHexString(freshnessProofValue));
				}
				if(!Arrays.equals(witnessedCommitment, freshnessProofCommitment)) {
					logger.log(Level.INFO, "witnessed commitment: "+Utils.byteArrayAsHexString(witnessedCommitment)+
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
	
	
	private PerformUpdateRequest createPerformUpdateRequest(List<Map.Entry<byte[], byte[]>> adsModifications, int validAt) {
		Update.Builder update = Update.newBuilder()
				.setValidAtCommitmentNumber(validAt);
		Set<Account> accounts = new HashSet<>();
		for(Map.Entry<byte[], byte[]> adsModification : adsModifications) {
			ADSModification modification = ADSModification.newBuilder()
					.setAdsId(ByteString.copyFrom(adsModification.getKey()))
					.setNewValue(ByteString.copyFrom(adsModification.getValue()))
					.build();
			update.addModifications(modification);
			accounts.addAll(this.adsIdToOwners.get(ByteBuffer.wrap(adsModification.getKey())));
		}
		PerformUpdateRequest request = createPerformUpdateRequest(update.build(), 
				accounts.stream().collect(Collectors.toList()));
		return request;
	}
	
	
	private PerformUpdateRequest createPerformUpdateRequest(byte[] adsId, byte[] newValue, int validAt) {
		return createPerformUpdateRequest(Arrays.asList(Map.entry(adsId, newValue)), validAt);
	}
			
	private static PerformUpdateRequest createPerformUpdateRequest(Update update, List<Account> accounts) {
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
	
	private ProveADSRootRequest createProveADSRootRequest(byte[] adsId) {
		return ProveADSRootRequest.newBuilder().setAdsId(ByteString.copyFrom(adsId)).build();
	}
	
	private static ProveADSRootResponse parseProveADSResponse(byte[] adsRootProof) {
		try {
			ProveADSRootResponse response = ProveADSRootResponse.parseFrom(adsRootProof);
			return response;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());

		}
	}
	
	private static boolean parsePerformUpdateResponse(byte[] response) {
		try {
			return PerformUpdateResponse.parseFrom(response).getAccepted();
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
		
	private static List<Account> getSortedListOfAccounts(int i, int maxClientsPerADS, 
			List<Account> accounts){
		BitSet bs = BitSet.valueOf(new long[]{i});
		if(bs.cardinality() > maxClientsPerADS) {
			return null;
		}
		List<Account> subset = new ArrayList<>();
		for(int idx = 0; idx < bs.length(); idx++) {
			if(bs.get(idx)) {
				subset.add(accounts.get(idx));
			}
		}
		return subset;
	}
	
	
}
