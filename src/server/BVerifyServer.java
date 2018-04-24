package server;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
	private List<IssueRequest> issueRequests;
	private List<RedeemRequest> redeemRequests;
	private List<TransferRequest> transferRequests;

	public BVerifyServer(String base) {
		this.pki = new PKIDirectory(base + "/pki/");
		this.clientadsManager = new ClientADSManager(base + "/client-ads/");
		this.serveradsManager = new ServerADSManager(base + "/server-ads/");
		
		this.issueRequests = new ArrayList<>();
		this.redeemRequests = new ArrayList<>();
		this.transferRequests = new ArrayList<>();
	}

	@Override
	public boolean startIssueReceipt(byte[] requestIssueMessage) {
		try {
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
			
			// and look up the current ads commitment 
			byte[] currentADSCommitment = this.serveradsManager.get(adsKey);

			// now load the client ads
			AuthenticatedSetServer ads = this.clientadsManager.getADS(adsKey);
						
			// and insert the receipt authentication information 
			// into the client ADS
			byte[] receiptHash = CryptographicDigest.hash(receipt.toByteArray());
			ads.insert(receiptHash);
			
			// get the new commitment 
			byte[] newADSCommitment = ads.commitment();
			assert !Arrays.equals(newADSCommitment, currentADSCommitment);
			
			// stage the updated client ads for a commit
			boolean success = this.clientadsManager.preCommitADS(ads, adsKey);
			
			if(!success) {
				return false;
			}
			
			// schedule the overall request to try and commit later
			IssueRequest ir = new IssueRequest(issuer, recepient, receipt, adsKey,
					currentADSCommitment, newADSCommitment);
			this.issueRequests.add(ir);

			return true;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean startRedeemReceipt(byte[] requestRedeemMessage) {
		try {
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
			
			// and look up the current ads commitment 
			byte[] currentADSCommitment = this.serveradsManager.get(adsKey);

			// now load the client ads
			AuthenticatedSetServer ads = this.clientadsManager.getADS(adsKey);
						
			// and delete the receipt
			// and update the authentication information 
			ads.delete(receiptHash);
			
			// get the new commitment 
			byte[] newADSCommitment = ads.commitment();
			assert !Arrays.equals(newADSCommitment, currentADSCommitment);
			
			// stage the updated client ads for a commit
			boolean success = this.clientadsManager.preCommitADS(ads, adsKey);
			
			if(!success) {
				return false;
			}
			
			// schedule the overall request to try and commit later
			RedeemRequest rr = new RedeemRequest(issuer, owner, receiptHash, adsKey,
					currentADSCommitment, newADSCommitment);
			this.redeemRequests.add(rr);

			return true;
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean startTransferReceipt(byte[] requestTransferMessage) {
		try {
			TransferReceiptRequest request = TransferReceiptRequest.parseFrom(requestTransferMessage);
			String issuerUUID = request.getIssuerId();
			String currentOwnerUUID = request.getCurrentOwnerId();
			String newOwnerUUID = request.getNewOwnerId();
			byte[] receiptHash = request.getReceiptHash().toByteArray();
			
			// lookup the accounts
			Account issuer = this.pki.getAccount(issuerUUID);
			Account currentOwner = this.pki.getAccount(currentOwnerUUID);
			Account newOwner = this.pki.getAccount(newOwnerUUID);

			// calculate the corresponding  ads keys
			// and look up the adses
			
			Set<Account> ads1accounts = new HashSet<>();
			ads1accounts.add(issuer);
			ads1accounts.add(currentOwner);
			byte[] ads1Key = CryptographicUtils.setOfAccountsToADSKey(ads1accounts);
			byte[] currentOwnerAdsValueOld = this.serveradsManager.get(ads1Key);
			MPTSetFull ads1 = (MPTSetFull) this.clientadsManager.getADS(ads1Key);
			if(!ads1.inSet(receiptHash)) {
				return false;
			}	
			MerklePrefixTrie proofCurrentOwnerAdsOld = (new MPTSetPartial(ads1, receiptHash)).serialize();
			
			Set<Account> ads2accounts = new HashSet<>();
			ads2accounts.add(issuer);
			ads2accounts.add(newOwner);
			byte[] ads2Key = CryptographicUtils.setOfAccountsToADSKey(ads2accounts);
			byte[] newOwnerAdsValueOld = this.serveradsManager.get(ads2Key);
			MPTSetFull ads2 = (MPTSetFull) this.clientadsManager.getADS(ads2Key);
			if(ads2.inSet(receiptHash)) {
				return false;
			}
			MerklePrefixTrie proofNewOwnerAdsOld = (new MPTSetPartial(ads2, receiptHash)).serialize();
			
			// now move the receipt from one ads to the other and 
			// create the corresponding proofs
			ads1.delete(receiptHash);
			ads2.insert(receiptHash);
			
			byte[] currentOwnerAdsValueNew = ads1.commitment();
			MerklePrefixTrie proofCurrentOwnerAdsNew = (new MPTSetPartial(ads1, receiptHash)).serialize();
			byte[] newOwnerAdsValueNew = ads2.commitment();
			MerklePrefixTrie proofNewOwnerAdsNew = (new MPTSetPartial(ads2, receiptHash)).serialize();
			
			// pre-commit the new adses
			this.clientadsManager.preCommitADS(ads1, ads1Key);
			this.clientadsManager.preCommitADS(ads2, ads2Key);
			
			// schedule the overall request to try and commit later
			TransferRequest tr = new TransferRequest(
					issuer, currentOwner, newOwner, receiptHash,
					ads1Key, ads2Key,
					currentOwnerAdsValueOld,
					proofCurrentOwnerAdsOld,
					currentOwnerAdsValueNew,
					proofCurrentOwnerAdsNew,
					newOwnerAdsValueOld,
					proofNewOwnerAdsOld,
					newOwnerAdsValueNew,
					proofNewOwnerAdsNew);
			this.transferRequests.add(tr);
			return true;
			// move the receipt from one ads to another 
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] getUpdates(byte[] updateRequest) {
		try {
			GetUpdatesRequest request = GetUpdatesRequest.parseFrom(updateRequest);

			// parse the keys
			List<byte[]> keys = new ArrayList<>();
			List<ByteString> keyByteStrings = request.getKeysList();
			for (ByteString key : keyByteStrings) {
				keys.add(key.toByteArray());
			}
			int from = request.getFromCommitNumber();
			return this.serveradsManager.getUpdate(from, keys);

		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
		return null;
	}

	
	private boolean attemptCommit() {
		// pre-commit all the updates
		for (IssueRequest ir : this.issueRequests) {
			this.serveradsManager.preCommitChange(ir.getADSKey(), ir.getNewValue());
		}
		for (RedeemRequest rr : this.redeemRequests) {
			this.serveradsManager.preCommitChange(rr.getADSKey(), rr.getNewValue());
		}
		for (TransferRequest tr : this.transferRequests) {
			this.serveradsManager.preCommitChange(tr.getCurrentOwnerAdsKey(), tr.getCurrentOwnerAdsValueNew());
			this.serveradsManager.preCommitChange(tr.getNewOwnerAdsKey(), tr.getNewOwnerAdsValueNew());
		}
		
		// add in the auth proof to all updates
		for (IssueRequest ir : this.issueRequests) {
			List<byte[]> keys = new ArrayList<>();
			keys.add(ir.getADSKey());
			MerklePrefixTrie authProof = this.serveradsManager.getProof(keys);
			ir.setAuthenticationProof(authProof);
		}
		for (RedeemRequest rr : this.redeemRequests) {
			List<byte[]> keys = new ArrayList<>();
			keys.add(rr.getADSKey());
			MerklePrefixTrie authProof = this.serveradsManager.getProof(keys);
			rr.setAuthenticationProof(authProof);
		}
		for (TransferRequest tr : this.transferRequests) {
			List<byte[]> keys = new ArrayList<>();
			keys.add(tr.getCurrentOwnerAdsKey());
			keys.add(tr.getNewOwnerAdsKey());
			MerklePrefixTrie authProof = this.serveradsManager.getProof(keys);
			tr.setAuthenticationProof(authProof);
		}
		
		// send proofs and wait to collect the signature
		
		// commit or abort!
		
		return true;
	}

}
