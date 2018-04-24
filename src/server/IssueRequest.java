package server;

import pki.Account;

public class IssueRequest {
	
	private final Account issuer;
	private final Account recepient;
	private final byte[] receiptData;
	private final byte[] adsKey;
	private final byte[] currentValue;
	private final byte[] newValue;
	
	public IssueRequest(Account issuer, Account recepient,  
			byte[] receiptData, byte[] adsKey, byte[] currentValue,
			byte[] newValue) {
		this.issuer = issuer;
		this.recepient = recepient;
		this.receiptData = receiptData;
		this.adsKey = adsKey;
		this.currentValue = currentValue;
		this.newValue = newValue;
	}
	
	public Account getIssuer() {
		return this.issuer;
	}
	
	public Account getRecepient() {
		return this.recepient;
	}
	
	public byte[] getReceiptData() {
		return this.receiptData;
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
