package server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicUtils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;
import mpt.set.MPTSetPartial;
import pki.Account;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.BVerifyAPIMessageSerialization.GetUpdatesRequest;
import serialization.BVerifyAPIMessageSerialization.IssueReceiptRequest;
import serialization.BVerifyAPIMessageSerialization.Receipt;
import serialization.BVerifyAPIMessageSerialization.RedeemReceiptRequest;
import serialization.BVerifyAPIMessageSerialization.TransferReceiptRequest;
import serialization.MptSerialization.MerklePrefixTrie;

public class BVerifyServer implements BVerifyProtocolServerAPI {

	/**
	 * Public Key Infrastructure - for identifying clients. For now this is mocked,
	 * but there are a variety of different possible ways to implement this.
	 */
	protected final PKIDirectory pki;

	/**
	 * RMI (or other RPC framework) for sending requests
	 */
	protected final ClientProvider provider;
	
	/**
	 * Client ADSes - stored on disk
	 */
	protected final ClientADSManager clientadsManager;

	/**
	 * Server (Authentication) ADSes - stored in memory
	 */
	protected final ServerADSManager serveradsManager;
	
	/**
	 * Changes to be applied. We batch changes for efficiency we keep track of all
	 * requests and try to apply them all at once.
	 */
	private Set<Request> requests;
	
	/**
	 * We use read-write locks to handle concurrent client requests 
	 * from the server
	 */
	protected final ReadWriteLock rwLock = new ReentrantReadWriteLock();
	
	/**
	 * Also we may need to make requests to multiple clients 
	 * and these requests should be done in parallel
	 */
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public BVerifyServer(String base) {
		this.pki = new PKIDirectory(base + "/pki/");
		this.provider = new ClientProvider();
		this.clientadsManager = new ClientADSManager(base + "/client-ads/");
		this.serveradsManager = new ServerADSManager(base + "/server-ads/");	
		this.requests = new HashSet<>();
	}

	@Override
	public boolean startIssueReceipt(byte[] requestIssueMessage) {
		try {
			this.rwLock.readLock().lock();
			// parse the request message
			IssueReceiptRequest request = IssueReceiptRequest.parseFrom(requestIssueMessage);
			String issuerUUID = request.getIssuerId();
			String recepientUUID = request.getRecepientId();
			// the receipt data is the actual receipt
			Receipt receipt = request.getReceipt();
			
			// lookup the accounts
			Account issuer = this.pki.getAccount(issuerUUID);
			Account recepient = this.pki.getAccount(recepientUUID);
			Set<Account> accounts = new HashSet<>();
			accounts.add(issuer);
			accounts.add(recepient);
			
			// calculate the client ads key
			byte[] adsKey = CryptographicUtils.setOfAccountsToADSKey(accounts);

			// now load the client ads
			AuthenticatedSetServer ads = this.clientadsManager.getADS(adsKey);
						
			// and insert the receipt authentication information 
			// into the client ADS
			byte[] receiptHash = CryptographicDigest.hash(receipt.toByteArray());
			ads.insert(receiptHash);
			
			// get the new commitment 
			byte[] newADSCommitment = ads.commitment();
			
			// stage the updated client ads for a commit
			boolean success = this.clientadsManager.preCommit(ads, adsKey);
			
			if(!success) {
				this.rwLock.readLock().unlock();
				return false;
			}
			
			// schedule the overall request to try and commit later
			IssueRequest ir = new IssueRequest(issuer, recepient, receipt, adsKey,
					newADSCommitment);
			
			// the request set is not threadsafe so we need to gaurd access to it
			synchronized(this) {
				this.requests.add(ir);	
			}
			
			this.rwLock.readLock().unlock();
			return true;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			
			this.rwLock.readLock().unlock();
			return false;
		}
	}

	@Override
	public boolean startRedeemReceipt(byte[] requestRedeemMessage) {
		try {
			this.rwLock.readLock().lock();
			// parse the request message
			RedeemReceiptRequest request = RedeemReceiptRequest.parseFrom(requestRedeemMessage);
			String issuerUUID = request.getIssuerId(); 
			String ownerUUID = request.getOwnerId();
			byte[] receiptHash = request.getReceiptHash().toByteArray();
			
			// lookup the accounts
			Account issuer = this.pki.getAccount(issuerUUID);
			Account owner = this.pki.getAccount(ownerUUID);
			Set<Account> accounts = new HashSet<>();
			accounts.add(issuer);
			accounts.add(owner);
			
			// calculate the client ads key
			byte[] adsKey = CryptographicUtils.setOfAccountsToADSKey(accounts);
			
			// now load the client ads
			AuthenticatedSetServer ads = this.clientadsManager.getADS(adsKey);
						
			// and delete the receipt
			// and update the authentication information 
			ads.delete(receiptHash);
			
			// get the new commitment 
			byte[] newADSCommitment = ads.commitment();
			
			// stage the updated client ads for a commit
			boolean success = this.clientadsManager.preCommit(ads, adsKey);
			
			if(!success) {
				this.rwLock.readLock().unlock();
				return false;
			}
			
			// schedule the overall request to try and commit later
			RedeemRequest rr = new RedeemRequest(issuer, owner, receiptHash, adsKey,
					newADSCommitment);
			
			synchronized(this) {
				this.requests.add(rr);				
			}
			
			this.rwLock.readLock().unlock();
			return true;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			this.rwLock.readLock().unlock();
			return false;
		}
	}

	@Override
	public boolean startTransferReceipt(byte[] requestTransferMessage) {
		try {
			this.rwLock.readLock().lock();
			TransferReceiptRequest request = TransferReceiptRequest.parseFrom(requestTransferMessage);
			String issuerUUID = request.getIssuerId();
			String currentOwnerUUID = request.getCurrentOwnerId();
			String newOwnerUUID = request.getNewOwnerId();
			byte[] receiptHash = request.getReceiptHash().toByteArray();
			
			// lookup the accounts
			Account issuer = this.pki.getAccount(issuerUUID);
			Account currentOwner = this.pki.getAccount(currentOwnerUUID);
			Account newOwner = this.pki.getAccount(newOwnerUUID);

			// calculate the corresponding ADSkeys
			// and look up the ADSes
			
			Set<Account> ads1accounts = new HashSet<>();
			ads1accounts.add(issuer);
			ads1accounts.add(currentOwner);
			byte[] ads1Key = CryptographicUtils.setOfAccountsToADSKey(ads1accounts);
			MPTSetFull ads1 = (MPTSetFull) this.clientadsManager.getADS(ads1Key);
			if(!ads1.inSet(receiptHash)) {
				return false;
			}	
			MerklePrefixTrie proofCurrentOwnerAdsOld = (new MPTSetPartial(ads1, receiptHash)).serialize();
			
			Set<Account> ads2accounts = new HashSet<>();
			ads2accounts.add(issuer);
			ads2accounts.add(newOwner);
			byte[] ads2Key = CryptographicUtils.setOfAccountsToADSKey(ads2accounts);
			MPTSetFull ads2 = (MPTSetFull) this.clientadsManager.getADS(ads2Key);
			if(ads2.inSet(receiptHash)) {
				this.rwLock.readLock().unlock();
				return false;
			}
			
			// now move the receipt from one ads to the other and 
			// create the corresponding proofs
			ads1.delete(receiptHash);
			ads2.insert(receiptHash);
			
			byte[] currentOwnerAdsValueNew = ads1.commitment();
			MerklePrefixTrie proofCurrentOwnerAdsNew = (new MPTSetPartial(ads1, receiptHash)).serialize();
			byte[] newOwnerAdsValueNew = ads2.commitment();
			MerklePrefixTrie proofNewOwnerAdsNew = (new MPTSetPartial(ads2, receiptHash)).serialize();
			
			// pre-commit the new adses
			this.clientadsManager.preCommit(ads1, ads1Key);
			this.clientadsManager.preCommit(ads2, ads2Key);
			
			// schedule the overall request to try and commit later
			TransferRequest tr = new TransferRequest(
					issuer, currentOwner, newOwner, receiptHash,
					ads1Key, ads2Key,
					proofCurrentOwnerAdsOld,
					currentOwnerAdsValueNew,
					proofCurrentOwnerAdsNew,
					newOwnerAdsValueNew,
					proofNewOwnerAdsNew);
			synchronized(this) {
				this.requests.add(tr);
			}
			this.rwLock.readLock().unlock();
			return true;
			// move the receipt from one ads to another 
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			this.rwLock.readLock().unlock();
			return false;
		}
	}

	@Override
	public byte[] getUpdates(byte[] updateRequest) {
		try {
			this.rwLock.readLock().lock();
			GetUpdatesRequest request = GetUpdatesRequest.parseFrom(updateRequest);

			// parse the keys
			List<byte[]> keys = new ArrayList<>();
			List<ByteString> keyByteStrings = request.getKeysList();
			for (ByteString key : keyByteStrings) {
				keys.add(key.toByteArray());
			}
			int from = request.getFromCommitNumber();
			this.rwLock.readLock().unlock();
			return this.serveradsManager.getUpdate(from, keys);

		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			this.rwLock.readLock().unlock();
			return null;
		}
	}

	public boolean attemptCommit() {
		// pre-commit all the updates
		// to update the authentication information
		this.rwLock.writeLock().lock();
		for (Request r : this.requests) {
			for(Map.Entry<byte[], byte[]> kvUpdate : r.getUpdatedKeyValues()) {
				this.serveradsManager.preCommit(kvUpdate.getKey(), kvUpdate.getValue());
			}
		}
		
		// add the authentication proofs
		for (Request r : this.requests) {
			List<byte[]> keys = r.getUpdatedKeyValues().stream().map(x -> x.getKey()).collect(Collectors.toList());
			MerklePrefixTrie authProof = this.serveradsManager.getProof(keys);
			r.setAuthenticationProof(authProof);
		}
		
		// now time to collect the approvals
		byte[] commitmentToBeSigned = this.serveradsManager.commitment();
		Collection<Callable<Boolean>> approvals = new ArrayList<Callable<Boolean>>();
		
		for (Request r : this.requests) {
			byte[] message = r.serialize();
			for (Account a : r.sendRequestTo()) {
				MakeRequestVerifyResponseCallback mr = new MakeRequestVerifyResponseCallback(
						message, a, commitmentToBeSigned, r, this.provider);
				approvals.add(mr);
			}
		}
		
		// send proofs and wait to collect the signature
		boolean commit = true;
		try {
			List<Future<Boolean>> results = WORKERS.invokeAll(approvals, TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : results) {
				Boolean resultBool = result.get();
				commit = commit && resultBool.booleanValue();
			}
		} catch (InterruptedException | ExecutionException e) {
			commit = false;
			e.printStackTrace();
		}
		if(commit) {
			this.serveradsManager.commit();
			this.clientadsManager.commit();
			this.rwLock.writeLock().unlock();
			return true;
		}
		this.serveradsManager.abort();
		this.clientadsManager.abort();
		this.rwLock.writeLock().lock();
		return false;
	}

}
