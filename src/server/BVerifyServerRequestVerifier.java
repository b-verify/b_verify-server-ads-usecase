package server;

import java.rmi.RemoteException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import pki.Account;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;

/**
 * Locking Discipline + Concurrency:
 * 		the client API can be exposed for concurrent calls, but 
 * 		whenever a commit happens, lock.writeLock is acquired by 
 * 		the applier thread, and the API should be frozen
 * 		while the commit takes place 
 * 
 * @author henryaspegren
 *
 */
public class BVerifyServerRequestVerifier implements BVerifyProtocolServerAPI {
	private static final Logger logger = Logger.getLogger(BVerifyServerRequestVerifier.class.getName());
	
	/**
	 * Shared data!
	 */
	private final ReadWriteLock lock;
	private final ADSManager adsManager;
	private final BlockingQueue<PerformUpdateRequest> updatesToBeCommited;
	
	/**
	 * If the server returns ACCEPTED - it PROMISES to include 
	 * this update in the next commitment 
	 */
	private static final byte[] ACCEPTED = PerformUpdateResponse.newBuilder()
			.setAccepted(true)
			.build()
			.toByteArray();
	
	/**
	 * If the server returns REJECTED - the update will not 
	 * be included in the next commitment
	 */
	private static final byte[] REJECTED = PerformUpdateResponse.newBuilder()
			.setAccepted(false)
			.build()
			.toByteArray();

	public BVerifyServerRequestVerifier(ReadWriteLock lock,
			BlockingQueue<PerformUpdateRequest> update, ADSManager ads) {
		this.lock = lock;
		this.adsManager = ads;
		this.updatesToBeCommited = update;
	}
	
	@Override
	public byte[] performUpdate(byte[] performUpdatesRequestMsg) {
		try {
			logger.log(Level.FINE, "perform update request recieved");
			
			// #1 parse the message
			PerformUpdateRequest request = PerformUpdateRequest.parseFrom(performUpdatesRequestMsg);
			
			// (AQUIRE READ LOCK)
			this.lock.readLock().lock();
						
			// #2 check that the update is for the next commitment 
			int nextCommitment = this.adsManager.getCurrentCommitmentNumber()+1;
			int validAt = request.getUpdate().getValidAtCommitmentNumber();
			if(nextCommitment != validAt) {
				logger.log(Level.WARNING, "update rejected... valid only at commitment: "+
							validAt+" but next commitment is: "+nextCommitment);
				this.lock.readLock().unlock();
				return REJECTED;
			}
			
			// #3 go through all the ADS modifications
			//		and determine who must sign the update
			Set<Account> needToSign = new HashSet<>();
			for(ADSModification adsModifcation : request.getUpdate().getModificationsList()) {
				byte[] adsKey = adsModifcation.getAdsId().toByteArray();
				Set<Account> owners = this.adsManager.getADSOwners(adsKey);
				needToSign.addAll(owners);
			}
			
			// #4 verify the signatures
			List<Account> needToSignList = needToSign.stream().collect(Collectors.toList());
			// canonically sort accounts
			Collections.sort(needToSignList);
			if(needToSign.size() != request.getSignaturesCount()) {
				logger.log(Level.WARNING, "update rejected... not enough signatures");
				this.lock.readLock().unlock();
				return REJECTED;
			}
			for(int i = 0; i < needToSign.size(); i++) {
				Account a = needToSignList.get(i);
				byte[] sig = request.getSignatures(i).toByteArray();
				// witness is the entire update 
				byte[] witness = CryptographicDigest.hash(request.getUpdate().toByteArray());
				boolean signed = CryptographicSignature.verify(witness, sig, a.getPublicKey());
				if(!signed) {
					logger.log(Level.WARNING, "update rejected... invalid signature");
					this.lock.readLock().unlock();
					return REJECTED;
				}
			}
			
			// #5 if all signatures verify create the update and
			// 	 schedule the update to be committed
			this.updatesToBeCommited.add(request);
			logger.log(Level.FINE, "update accepted");
			this.lock.readLock().unlock();
			return ACCEPTED;
		} 	catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.FINE, "update rejected");
			this.lock.readLock().unlock();
			return REJECTED;
		}
	}


	@Override
	public byte[] proveADSRoot(byte[] adsRootRequest) throws RemoteException {
		try {
			logger.log(Level.FINE, "prove ads root request recieved");
			this.lock.readLock().lock();
			ProveADSRootRequest request = ProveADSRootRequest.parseFrom(adsRootRequest);
			byte[] adsId = request.getAdsId().toByteArray();
			ADSRootProof proof = this.adsManager.getADSRootProof(adsId);
			this.lock.readLock().unlock();
			return ProveADSRootResponse.newBuilder().setProof(proof).build().toByteArray();
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "bad request");
			this.lock.readLock().unlock();
			return null;
		}
	}

	@Override
	public List<byte[]> commitments() throws RemoteException {
		logger.log(Level.FINE, "get commitments request recieved");
		this.lock.readLock().lock();
		List<byte[]> commitments = this.adsManager.getCommitments();
		this.lock.readLock().unlock();
		return commitments;
	}


}
