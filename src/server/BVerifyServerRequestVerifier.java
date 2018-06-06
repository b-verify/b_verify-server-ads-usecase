package server;

import java.rmi.RemoteException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import pki.Account;
import serialization.generated.BVerifyAPIMessageSerialization.ADSProofUpdates;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.GetADSProofUpdatesRequest;
import serialization.generated.BVerifyAPIMessageSerialization.GetADSProofUpdatesResponse;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;

/**
 * Locking Discipline + Concurrency: the client API can be exposed for
 * concurrent calls, but whenever a commit happens, lock.writeLock is acquired
 * by the applier thread, and the API should be frozen while the commit takes
 * place
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
	 * If the server returns ACCEPTED - it PROMISES to include this update in the
	 * next commitment
	 */
	private static final byte[] ACCEPTED = PerformUpdateResponse.newBuilder().setAccepted(true).build().toByteArray();

	/**
	 * If the server returns REJECTED - the update will not be included in the next
	 * commitment
	 */
	private static final byte[] REJECTED = PerformUpdateResponse.newBuilder().setAccepted(false).build().toByteArray();

	/**
	 * Optionally can disable the checking of signatures to speed test cases
	 */
	private final boolean requireSignatures;

	public BVerifyServerRequestVerifier(ReadWriteLock lock, BlockingQueue<PerformUpdateRequest> update, ADSManager ads,
			boolean requireSignatures) {
		this.lock = lock;
		this.adsManager = ads;
		this.updatesToBeCommited = update;
		this.requireSignatures = requireSignatures;
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
			int nextCommitment = this.adsManager.getCurrentCommitmentNumber() + 1;
			int validAt = request.getUpdate().getValidAtCommitmentNumber();
			if (nextCommitment != validAt) {
				logger.log(Level.WARNING, "update rejected... valid only at commitment: " + validAt
						+ " but next commitment is: " + nextCommitment);
				this.lock.readLock().unlock();
				return REJECTED;
			}

			// we skip checking signatures IF signature checks are on and it
			// is a non-initial update (we skip checking signatures for the initial updates
			// to speed up tests)
			if (this.requireSignatures && nextCommitment != 0) {
				// #3 go through all the ADS modifications
				// and determine who must sign the update

				List<Account> needToSign = request.getUpdate().getModificationsList().stream()
						.flatMap(adsModification -> {
							byte[] adsKey = adsModification.getAdsId().toByteArray();
							return this.adsManager.getADSOwners(adsKey).stream();
						}).collect(Collectors.toSet()).stream().collect(Collectors.toList());
				// canonically sort accounts
				Collections.sort(needToSign);

				// #4 verify the signatures
				if (needToSign.size() != request.getSignaturesCount()) {
					logger.log(Level.WARNING, "update rejected... not enough signatures");
					this.lock.readLock().unlock();
					return REJECTED;
				}

				// witness is the entire update
				byte[] witness = CryptographicDigest.hash(request.getUpdate().toByteArray());
				boolean result = IntStream.range(0, needToSign.size()).mapToObj(i -> {
					Account a = needToSign.get(i);
					byte[] sig = request.getSignatures(i).toByteArray();
					boolean signed = CryptographicSignature.verify(witness, sig, a.getPublicKey());
					if (!signed) {
						logger.log(Level.WARNING, "update account " + a + " signature invalid");
					}
					return signed;
				}).reduce(Boolean::logicalAnd).get().booleanValue();
				if (!result) {
					logger.log(Level.WARNING, "request: " + request + " rejected!");
					this.lock.readLock().unlock();
					return REJECTED;
				}
			}

			// #5 if all signatures verify create the update and
			// schedule the update to be committed
			this.updatesToBeCommited.add(request);
			logger.log(Level.FINE, "update accepted");
			this.lock.readLock().unlock();
			return ACCEPTED;
		} catch (InvalidProtocolBufferException e) {
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
	public byte[] getADSProofUpdates(byte[] proofUpdatesRequest) throws RemoteException {
		try {
			logger.log(Level.FINE, "update ads proof request recieved");
			this.lock.readLock().lock();
			GetADSProofUpdatesRequest request = GetADSProofUpdatesRequest.parseFrom(proofUpdatesRequest);
			byte[] adsId = request.getAdsId().toByteArray();
			int fromCommitment = request.getFromCommitment();
			ADSProofUpdates updates = this.adsManager.getADSProofUpdates(adsId, fromCommitment);
			this.lock.readLock().unlock();
			return GetADSProofUpdatesResponse.newBuilder().setUpdates(updates).build().toByteArray();
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "bad request");
			this.lock.readLock().unlock();
			return null;
		}
	}
	
	// BENCHMARKING ONLY
	public byte[] proveADSRootMICROBENCHMARK(byte[] adsId) {
		ADSRootProof proof = this.adsManager.getADSRootProof(adsId);
		return proof.toByteArray();
	}
	
	// BENCHMARKING ONLY
	public byte[] getProofUpdatesMICROBENCHMARK(byte[] adsId) {
		ADSProofUpdates updates = this.adsManager.getADSProofUpdates(adsId);
		return updates.toByteArray();
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
