package server;

import java.rmi.RemoteException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import pki.Account;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.GetADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveUpdateResponse;
import serialization.generated.MptSerialization.MerklePrefixTrie;

public class BVerifyServerRequestHandler implements BVerifyProtocolServerAPI {
	private static final Logger logger = Logger.getLogger(BVerifyServerRequestHandler.class.getName());
	
	// shared data
	private final ADSManager adsManager;
	private BlockingQueue<PerformUpdateRequest> updatesToBeCommited;
	
	private static final byte[] ACCEPTED = PerformUpdateResponse.newBuilder()
			.setAccepted(true)
			.build()
			.toByteArray();
	
	private static final byte[] REJECTED = PerformUpdateResponse.newBuilder()
			.setAccepted(false)
			.build()
			.toByteArray();

	public BVerifyServerRequestHandler( 
			BlockingQueue<PerformUpdateRequest> update, ADSManager ads) {
		this.adsManager = ads;
		this.updatesToBeCommited = update;
	}
	
	@Override
	public byte[] performUpdate(byte[] performUpdatesRequestMsg) {
		try {
			logger.log(Level.FINE, "perform update request recieved");
			// #1 parse the message
			PerformUpdateRequest request = PerformUpdateRequest.parseFrom(performUpdatesRequestMsg);
						
			// #2 go through all the ADS modifications
			//		and determine who must sign the update
			Set<Account> needToSign = new HashSet<>();
			for(ADSModification adsModifcation : request.getUpdate().getModificationsList()) {
				byte[] adsKey = adsModifcation.getAdsId().toByteArray();
				Set<Account> owners = this.adsManager.getADSOwners(adsKey);
				needToSign.addAll(owners);
			}
			
			// #3 verify the signatures
			// canonically sort accounts
			List<Account> needToSignList = needToSign.stream().collect(Collectors.toList());
			Collections.sort(needToSignList);
			if(needToSign.size() != request.getSignaturesCount()) {
				logger.log(Level.FINE, "update rejected... not enough signatures");
				return REJECTED;
			}
			for(int i = 0; i < needToSign.size(); i++) {
				Account a = needToSignList.get(i);
				byte[] sig = request.getSignatures(i).toByteArray();
				// witness is the entire update + block height (block height omitted for now)
				byte[] witness = CryptographicDigest.hash(request.getUpdate().toByteArray());
				boolean signed = CryptographicSignature.verify(witness, sig, a.getPublicKey());
				if(!signed) {
					logger.log(Level.FINE, "update rejected... invalid signature");
					return REJECTED;
				}
			}
			
			// #5 if all signatures verify create the update and
			// 	 schedule the update to be committed
			this.updatesToBeCommited.add(request);
			logger.log(Level.FINE, "update accepted");
			return ACCEPTED;
			
		} 	catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.FINE, "update rejected");
			return REJECTED;
		}
	}

	@Override
	public byte[] proveUpdate(byte[] proveUpdateRequestMsg) throws RemoteException {
		try {
			logger.log(Level.FINE, "prove update request recieved");
			ProveUpdateRequest request = ProveUpdateRequest.parseFrom(proveUpdateRequestMsg);
			// parse the keys
			List<byte[]> keys = request.getAdsIdsList().stream()
					.map(x -> x.toByteArray())
					.collect(Collectors.toList());
			MerklePrefixTrie mpt = this.adsManager.getProof(keys);
			return ProveUpdateResponse.newBuilder().setProof(mpt).build().toByteArray();
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "bad request");
			return null;
		}
	}

	@Override
	public byte[] getADSRoot(byte[] adsRootRequest) throws RemoteException {
		try {
			GetADSRootRequest request = GetADSRootRequest.parseFrom(adsRootRequest);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "bad request");
			return null;
		}
		return null;
	}


}
