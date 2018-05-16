package integrationtest;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import client.Request;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryPartial;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import serialization.generated.BVerifyAPIMessageSerialization.Update;
import server.BVerifyServer;
import server.StartingData;

public class MockTester {
	
	private static final Logger logger = Logger.getLogger(MockTester.class.getName());

	private final BVerifyServer server;

	private final Request request;
	
	// the actual mappings 
	private final Map<ByteBuffer, PerformUpdateRequest> adsIdToLastUpdate;
	
	// pending updates
	private final List<Entry<byte[], PerformUpdateRequest>> pendingUpdates;
	private int pendingAcceptedCommitments;
	private int lastAcceptedCommitmentNumber;
	private final int batchSize;
	
	// commitments 
	private List<byte[]> commitments;
	
	// signatures may be omitted
	// (saves time when generating large
	// test cases)
	private final boolean requireSignatures;
	
	private static final int RETRY_PROOF_INTERVAL_MS = 10;
	
	public MockTester(StartingData initialData, BVerifyServer server, 
			int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, ""+" batch size: "+batchSize);
		this.server = server;
		this.requireSignatures = requireSignatures;
		
		// this is used to format requests 
		this.request = new Request(initialData);
										
		// (1) for each ADS_ID store the initial update
		this.adsIdToLastUpdate = new HashMap<>();
		for(PerformUpdateRequest initialUpdate : initialData.getInitialUpdates()) {
			for(ADSModification mod : initialUpdate.getUpdate().getModificationsList()) {
				this.adsIdToLastUpdate.put(ByteBuffer.wrap(mod.getAdsId().toByteArray()),
						initialUpdate);
			}
		}
				
		// batching
		this.pendingUpdates = new ArrayList<>();
		this.pendingAcceptedCommitments = 0;
		this.batchSize = batchSize;
		this.lastAcceptedCommitmentNumber = 0;
		
		// start with no commitments 
		this.commitments = new ArrayList<>();
		
		// get the first (initial) commitment
		this.waitAndGetNewCommitments();
		
		
		logger.log(Level.INFO, "asking for initial proofs");
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
		return Request.parsePerformUpdateResponse(res);
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
		PerformUpdateRequest updateRequest = this.request.createPerformUpdateRequest(adsModifications, 
				this.getNextCommitmentNumber(), this.requireSignatures);
		boolean response  = this.requestUpdate(updateRequest);
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
		ProveADSRootRequest request = Request.createProveADSRootRequest(adsId);
		try {
			// request a proof
			ProveADSRootResponse proofResponse = Request.parseProveADSResponse(
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

}
