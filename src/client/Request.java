package client;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import pki.Account;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.GetADSProofUpdatesRequest;
import serialization.generated.BVerifyAPIMessageSerialization.GetADSProofUpdatesResponse;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import serialization.generated.BVerifyAPIMessageSerialization.Update;
import server.StartingData;

public class Request {
	
	private final Map<ByteBuffer, List<Account>> adsIdToOwners;
	
	public Request(StartingData initialData) {
		this.adsIdToOwners = new HashMap<>();
		Map<ByteBuffer, Set<Account>> toOwners = new HashMap<>();
		for(Account a : initialData.getPKI().getAllAccounts()) {
			Set<byte[]> adsIds = a.getADSKeys();
			for(byte[] adsId : adsIds) {
				ByteBuffer key = ByteBuffer.wrap(adsId);
				Set<Account> accs = toOwners.get(key);
				if(accs == null) {
					accs = new HashSet<>();
				}
				accs.add(a);
				toOwners.put(key, accs);
			}
		}
		//  create a mapping from ADS_ID -> (sorted) [owners]
		for(Map.Entry<ByteBuffer, Set<Account>> entry : toOwners.entrySet()) {
			List<Account> owners = entry.getValue().stream().collect(Collectors.toList());
			Collections.sort(owners);
			this.adsIdToOwners.put(entry.getKey(), owners);
		}
	}
	
	public List<byte[]> getADSIds(){
		// we sort this so that it is deterministic
		List<ByteBuffer> result = this.adsIdToOwners.keySet().stream().collect(Collectors.toList());
		Collections.sort(result);
		return result.stream().map(x -> x.array()).collect(Collectors.toList());
	}
	
	public List<Account> getAccountsThatMustSign(List<Map.Entry<byte[], byte[]>> adsModifications){
		Set<Account> accounts = new HashSet<>();
		for(Map.Entry<byte[], byte[]> adsModification : adsModifications) {
			accounts.addAll(this.adsIdToOwners.get(ByteBuffer.wrap(adsModification.getKey())));
		}
		List<Account> result = accounts.stream().collect(Collectors.toList());
		Collections.sort(result);
		return result;
	}
	
	public List<Account> getAccountsThatMustSignFromList(List<byte[]> adsIds){
		Set<Account> accounts = new HashSet<>();
		for(byte[] adsId : adsIds) {
			accounts.addAll(this.adsIdToOwners.get(ByteBuffer.wrap(adsId)));
		}
		List<Account> result = accounts.stream().collect(Collectors.toList());
		Collections.sort(result);
		return result;
	}
	
	public PerformUpdateRequest createPerformUpdateRequest(List<Map.Entry<byte[], byte[]>> adsModifications,
			int validAt, boolean requireSignatures) {
		Update.Builder update = Update.newBuilder()
				.setValidAtCommitmentNumber(validAt);
		// if include signatures, need to calculate signers, the witness
		// and actually have each person sign
		if(requireSignatures) {
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
		
	public PerformUpdateRequest createPerformUpdateRequest(byte[] adsId, byte[] newValue, 
			int validAt, boolean requireSignatures) {
		return this.createPerformUpdateRequest(Arrays.asList(Map.entry(adsId, newValue)),
				validAt, requireSignatures);
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
	
	public static GetADSProofUpdatesRequest createGetProofUpdatesReuqest(byte[] adsId, int fromCmt) {
		return GetADSProofUpdatesRequest.newBuilder()
				.setAdsId(ByteString.copyFrom(adsId))
				.setFromCommitment(fromCmt)
				.build();
	}
	
	public static GetADSProofUpdatesResponse parseGetProofUpdatesResponse(byte[] requestBytes) {
		try {
			return GetADSProofUpdatesResponse.parseFrom(requestBytes);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());

		}
	}
	
}
