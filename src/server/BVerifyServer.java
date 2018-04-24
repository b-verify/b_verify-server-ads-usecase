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
import pki.Account;
import pki.PKIDirectory;
import mpt.set.AuthenticatedSetClient;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;
import mpt.set.MPTSetPartial;
import serialization.BVerifyAPIMessageSerialization.GetUpdatesRequest;
import serialization.BVerifyAPIMessageSerialization.IssueReceiptRequest;
import serialization.BVerifyAPIMessageSerialization.RedeemReceiptRequest;
import serialization.BVerifyAPIMessageSerialization.TransferReceiptRequest;

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
			String issuerUUID = new String(request.getIssuerId().toByteArray());
			String recepientUUID = new String(request.getRecepientId().toByteArray());
			// the receipt data is the actual receipt
			byte[] receiptData = request.getReceiptData().toByteArray();
			
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
			byte[] receiptHash = CryptographicDigest.hash(receiptData);
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
			IssueRequest ir = new IssueRequest(issuer, recepient, receiptData, adsKey,
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
			String issuerUUID = new String(request.getIssuerId().toByteArray());
			String ownerUUID = new String(request.getOwnerId().toByteArray());
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
			String issuerUUID = new String(request.getIssuerId().toByteArray());
			String currentOwnerUUID = new String(request.getCurrentOwnerId().toByteArray());
			String newOwnerUUID = new String(request.getNewOwnerId().toByteArray());
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
			byte[] currentOwnerAds = this.serveradsManager.get(ads1Key);
			AuthenticatedSetServer ads1 = this.clientadsManager.getADS(ads1Key);
			if(!ads1.inSet(receiptHash)) {
				return false;
			}
			MPTSetFull fullOld = (MPTSetFull) ads1;
			AuthenticatedSetClient ads1client = new MPTSetPartial(fullOld, 
					receiptHash);
			
			byte[] proofOldAds = ads1client.serialize();
			
			Set<Account> ads2accounts = new HashSet<>();
			ads2accounts.add(issuer);
			ads2accounts.add(newOwner);
			byte[] ads2Key = CryptographicUtils.setOfAccountsToADSKey(ads2accounts);
			byte[] newOwnerAds = this.serveradsManager.get(ads2Key);
			AuthenticatedSetServer ads2 = this.clientadsManager.getADS(ads2Key);

			// move the receipt from one ads to another 
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
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

	private boolean tryToCommitEntries() {
		// start with issue requests
		for (IssueRequest ir : this.issueRequests) {
		
		}

		return true;
	}

}
