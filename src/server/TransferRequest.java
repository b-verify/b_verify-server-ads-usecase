package server;

import pki.Account;

public class TransferRequest {
	
	private final Account issuer;
	private final Account currentOwner;
	private final Account newOwner;
	private final byte[] receiptHash;
	private final byte[] currentOwnerAdsKey;
	private final byte[] newOwnerAdsKey;
	
	private final byte[] currentOwnerAdsValueOld;
	private final byte[] proofCurrentOwnerAdsOld;
	private final byte[] currentOwnerAdsValueNew;
	private final byte[] proofCurrentOwnerAdsNew;
	private final byte[] newOwnerAdsValueOld;
	private final byte[] proofNewOwnerAdsOld;
	private final byte[] newOwnerAdsValueNew;
	private final byte[] proofNewOwnerAdsNew;
	
	
	public TransferRequest(Account issuer, Account currentOwner,
			Account newOwner, byte[] receiptHash, 
			byte[] currentOwnerAdsKey, byte[] newOwnerAdsKey,
			byte[] currentOwnerAdsValueOld,
			byte[] proofCurrentOwnerAdsOld,
			byte[] currentOwnerAdsValueNew,
			byte[] proofCurrentOwnerAdsNew,
			byte[] newOwnerAdsValueOld,
			byte[] proofNewOwnerAdsOld,
			byte[] newOwnerAdsValueNew,
			byte[] proofNewOwnerAdsNew) {
		
		this.issuer = issuer;
		this.currentOwner = currentOwner;
		this.newOwner = newOwner;
		this.receiptHash = receiptHash;
		this.currentOwnerAdsKey = currentOwnerAdsKey;
		this.newOwnerAdsKey = newOwnerAdsKey;
		
		this.currentOwnerAdsValueOld = currentOwnerAdsValueOld;
		this.proofCurrentOwnerAdsOld = proofCurrentOwnerAdsOld;
		this.currentOwnerAdsValueNew = currentOwnerAdsValueNew;
		this.proofCurrentOwnerAdsNew = proofCurrentOwnerAdsNew;
		
		this.newOwnerAdsValueOld = newOwnerAdsValueOld;
		this.proofNewOwnerAdsOld = proofNewOwnerAdsOld;
		this.newOwnerAdsValueNew = newOwnerAdsValueNew;
		this.proofNewOwnerAdsNew = proofNewOwnerAdsNew;
		
	}


	public Account getIssuer() {
		return issuer;
	}


	public Account getCurrentOwner() {
		return currentOwner;
	}


	public Account getNewOwner() {
		return newOwner;
	}


	public byte[] getReceiptHash() {
		return receiptHash;
	}


	public byte[] getNewOwnerAdsKey() {
		return newOwnerAdsKey;
	}


	public byte[] getCurrentOwnerAdsKey() {
		return currentOwnerAdsKey;
	}


	public byte[] getCurrentOwnerAdsValueOld() {
		return currentOwnerAdsValueOld;
	}


	public byte[] getProofCurrentOwnerAdsOld() {
		return proofCurrentOwnerAdsOld;
	}


	public byte[] getCurrentOwnerAdsValueNew() {
		return currentOwnerAdsValueNew;
	}


	public byte[] getProofCurrentOwnerAdsNew() {
		return proofCurrentOwnerAdsNew;
	}


	public byte[] getNewOwnerAdsValueOld() {
		return newOwnerAdsValueOld;
	}


	public byte[] getProofNewOwnerAdsOld() {
		return proofNewOwnerAdsOld;
	}


	public byte[] getNewOwnerAdsValueNew() {
		return newOwnerAdsValueNew;
	}


	public byte[] getProofNewOwnerAdsNew() {
		return proofNewOwnerAdsNew;
	}

}
