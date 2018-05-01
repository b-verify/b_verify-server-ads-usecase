package server;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ADSModificationRequest;
import serialization.BVerifyAPIMessageSerialization.GetUpdatesRequest;
import serialization.BVerifyAPIMessageSerialization.RequestADSUpdates;

public class BVerifyServerRequestVerifier implements BVerifyProtocolServerAPI {
	
	// shared data
	private final ADSManager adsManager;
	private BlockingQueue<Update> updatesToBeCommited;

	public BVerifyServerRequestVerifier( 
			BlockingQueue<Update> update, ADSManager ads) {
		this.adsManager = ads;
		this.updatesToBeCommited = update;
	}
	
	@Override
	public boolean submitUpdates(byte[] adsUpdates) {
		try {
			// #1 parse the message
			RequestADSUpdates request = RequestADSUpdates.parseFrom(adsUpdates);
						
			// #2 go through all the ADS modifications
			//		to find all parties who need to have signed the 
			//		request
			List<Account> needToSign = new ArrayList<>();
			Set<ADSModification> modifications = new HashSet<>();
			for(ADSModificationRequest adsModifcation : request.getModificationsList()) {
				byte[] adsKey = adsModifcation.getAdsId().toByteArray();
				byte[] adsValue = adsModifcation.getNewValue().toByteArray();
				Set<Account> owners = this.adsManager.getADSOwners(adsKey);
				needToSign.addAll(owners);
				// # 3 create the actual ADS modifications
				ADSModification adsModification = new ADSModification(adsKey, adsValue);
				modifications.add(adsModification);
			}
			// canonically sort accounts
			Collections.sort(needToSign);
			
			// #4 verify the signatures
			List<byte[]> signatures = 
					request.getSignaturesList().stream()
					.map(x -> x.getSignature().toByteArray())
					.collect(Collectors.toList());
			if(needToSign.size() != signatures.size()) {
				return false;
			}
			for(int i = 0; i < signatures.size(); i++) {
				Account a = needToSign.get(i);
				byte[] sig = signatures.get(i);
				// witness for now is just the first modification
				byte[] witness = CryptographicDigest.hash(request.getModifications(0).toByteArray());
				boolean signed = CryptographicSignature.verify(witness, sig, a.getPublicKey());
				if(!signed) {
					return false;
				}
			}
			
			// #5 if all signatures verify create the update and
			// 	 schedule the update to be committed
			Update update = new Update(modifications, request);
			if(this.updatesToBeCommited.remainingCapacity() == 0) {
				return false;
			}else {
				this.updatesToBeCommited.add(update);
				return true;
			}
			
		} 	catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] getUpdates(byte[] updateRequest) throws RemoteException {
		try {
			GetUpdatesRequest request = GetUpdatesRequest.parseFrom(updateRequest);
			// parse the keys
			List<byte[]> keys = new ArrayList<>();
			List<ByteString> keyByteStrings = request.getKeysList();
			for (ByteString key : keyByteStrings) {
				keys.add(key.toByteArray());
			}
			int from = request.getFromCommitNumber();
			byte[] updates = this.adsManager.getUpdate(from, keys);
			return updates;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			return null;
		}
	}

}
