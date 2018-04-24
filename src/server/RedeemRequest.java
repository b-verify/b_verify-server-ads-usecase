package server;

import pki.Account;

public class RedeemRequest {
	
	private final Account issuer;
	private final Account owner;
	private final byte[] receiptHash;
	private final byte[] adsKey;
	private final byte[] currentValue;
	private final byte[] newValue;
	
	public RedeemRequest(Account issuer, Account owner,
			byte[] receiptHash, byte[] adsKey, byte[] currentValue,
			byte[] newValue) {
		this.issuer = issuer;
		this.owner = owner;
		this.receiptHash = receiptHash;
		this.adsKey = adsKey;
		this.currentValue = currentValue;
		this.newValue = newValue;
	}
	
	public Account getIssuer() {
		return this.issuer;
	}
	
	public Account getOwner() {
		return this.owner;
	}
	
	public byte[] getReceiptHash() {
		return this.receiptHash;
	}
	
	public byte[] getADSKey() {
		return this.adsKey;
	}
	
	public byte[] getCurrentValue() {
		return this.currentValue;
	}
	
	public byte[] getNewValue() {
		return this.newValue;
	}
	
}
