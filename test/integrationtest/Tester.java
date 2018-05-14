package integrationtest;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
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

public class Tester {
	private static final Logger logger = Logger.getLogger(Tester.class.getName());

	// server - for testing.
	private final BVerifyServer server;
	
	// the actual mappings (stored so that we can check the server)
	private final Map<ByteBuffer, byte[]> adsIdToValue;
	private final Map<ByteBuffer, PerformUpdateRequest> adsIdToLastUpdate;
	private final Map<ByteBuffer, List<Account>> adsIdToOwners;
	
	// commitments 
	private List<byte[]> commitments;
	
	// batch size of 1 means that we get a new commitment every test
	private final static int BATCH_SIZE = 1;

	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());
	
	public Tester(int nClients, int maxClientsPerADS) {
		this.adsIdToValue = new HashMap<>();
		this.adsIdToLastUpdate = new HashMap<>();
		this.adsIdToOwners = new HashMap<>();
		this.commitments = new ArrayList<>();
				
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
			logger.log(Level.INFO, "{"+adsAccounts+"} -> "+Utils.byteArrayAsHexString(adsId));
			ByteBuffer adsIdBuffer = ByteBuffer.wrap(adsId);
			
			this.adsIdToValue.put(adsIdBuffer, START_VALUE);
			this.adsIdToOwners.put(adsIdBuffer, adsAccounts);
			
			// create a request initializing this value
			PerformUpdateRequest initialUpdateRequest = this.createPerformUpdateRequest(adsId, START_VALUE, 0);
			this.adsIdToLastUpdate.put(adsIdBuffer, initialUpdateRequest);			
		}
		PKIDirectory pki = new PKIDirectory(accounts);
		logger.log(Level.INFO, "Number of ADSes: "+this.adsIdToOwners.size());
		
		logger.log(Level.INFO, "Starting the Server");
		this.server = new BVerifyServer(pki, BATCH_SIZE, 
				adsIdToLastUpdate.values().stream().collect(Collectors.toSet()));
		
		logger.log(Level.INFO, "Asking for initial proofs");
		boolean initialProofs = this.getAndCheckProofs();
		if(!initialProofs) {
			throw new RuntimeException("not correctly set up");
		}
	}
	
	public List<byte[]> getADSIds(){
		return this.adsIdToValue.keySet().stream().map(x -> x.array()).collect(Collectors.toList());
	}
	
	public boolean doUpdate(byte[] adsId, byte[] newValue) {
		PerformUpdateRequest updateRequest = this.createPerformUpdateRequest(adsId, newValue, 
				this.getNextCommitmentNumber());
		boolean response  = parsePerformUpdateResponse(
				this.server.getRequestHandler().performUpdate(updateRequest.toByteArray()));
		if(response) {
			this.adsIdToLastUpdate.put(ByteBuffer.wrap(adsId), updateRequest);
		}
		return response;
	}
	
	public boolean getAndCheckProofs() {
		// first get the commitments
		this.getCommitments();
		// then for each adsId -> value map
		for(Entry<ByteBuffer, byte[]> adsIdAndValue : this.adsIdToValue.entrySet()) {
			byte[] adsId = adsIdAndValue.getKey().array();
			logger.log(Level.INFO, "asking for proof for ADS ID: "+Utils.byteArrayAsHexString(adsId));
			ProveADSRootRequest request = this.createProveADSRootRequest(adsId);
			try {
				// request a proof
				ProveADSRootResponse proofResponse = parseProveADSResponse(
						this.server.getRequestHandler().proveADSRoot(request.toByteArray()));
				ADSRootProof proof = proofResponse.getProof();
				// check the proof
				PerformUpdateRequest lastUpdateRequest = this.adsIdToLastUpdate.get(adsIdAndValue.getKey());
				boolean correctProof = this.checkProof(adsId, lastUpdateRequest, proof);
				if(!correctProof) {
					logger.log(Level.INFO, "proof failed!");
					return false;
				}
			} catch (RemoteException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
		}
		return true;
	}
	
	public int getNextCommitmentNumber() {
		return this.commitments.size();
	}
	
	private void getCommitments() {
		List<byte[]> commitments;
		try {
			commitments = this.server.getRequestHandler().commitments();
			for(int i = 0 ; i < commitments.size(); i++) {
				if(i < this.commitments.size()) {
					if(!Arrays.equals(this.commitments.get(i), commitments.get(i))) {
						throw new RuntimeException("bug on server - something wrong");
					}
				}else {
					logger.log(Level.INFO, 
							"new commitment #"+i+" = "+Utils.byteArrayAsHexString(commitments.get(i)));
				}
			}
			this.commitments = commitments;
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private boolean checkProof(byte[] adsId, PerformUpdateRequest correctLastUpdateRequest, 
			ADSRootProof proof) {
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
			int updateCommitment = lastUpdate.getValidAtCommitmentNumber();
			byte[] commitment = this.commitments.get(updateCommitment);
			byte[] proofCommitment = updateProof.commitment();
			if(!Arrays.equals(commitment, updateProof.commitment())) {
				logger.log(Level.INFO, "proof commitment: "+Utils.byteArrayAsHexString(proofCommitment)+
										"\n witnessed commitment: "+Utils.byteArrayAsHexString(commitment));
				return false;
			}
			for(ADSModification adsModification : lastUpdate.getModificationsList()) {
				byte[] value = updateProof.get(adsModification.getAdsId().toByteArray());
				if(!Arrays.equals(value, adsModification.getNewValue().toByteArray())) {
					logger.log(Level.INFO, "ads modification for last update not applied");
					return false;
				}
			}
			// now check the freshness proof 
			int sizeOfFreshnessProof = (this.commitments.size()-1)-updateCommitment;
			if(proof.getFreshnessProofCount() != sizeOfFreshnessProof) {
				logger.log(Level.INFO, "incomplete freshness proof");
				return false;
			}
			// TODO check freshness proof correctly
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	
	private PerformUpdateRequest createPerformUpdateRequest(byte[] adsId, byte[] newValue, int validAt) {
		ADSModification modification = ADSModification.newBuilder()
				.setAdsId(ByteString.copyFrom(adsId))
				.setNewValue(ByteString.copyFrom(newValue))
				.build();
		Update update = Update.newBuilder()
				.addModifications(modification)
				.setValidAtCommitmentNumber(validAt)
				.build();
		List<Account> accounts = this.adsIdToOwners.get(ByteBuffer.wrap(adsId));
		PerformUpdateRequest request  = createPerformUpdateRequest(update, accounts);
		return request;
	}
			
	private PerformUpdateRequest createPerformUpdateRequest(Update update, List<Account> accounts) {
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
