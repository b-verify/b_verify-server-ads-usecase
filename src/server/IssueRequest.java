package server;

import com.google.protobuf.ByteString;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ReceiptIssueApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class IssueRequest {
	
	private final Account issuer;
	private final Account recepient;
	private final byte[] receiptData;
	private final byte[] adsKey;
	private final byte[] currentValue;
	private final byte[] newValue;
	
	private MerklePrefixTrie authProof;
	
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
	
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}
	
	public MerklePrefixTrie getAuthenticationProof() {
		return this.authProof;
	}
	
	public ReceiptIssueApprove serialize() {
		ReceiptIssueApprove.Builder builder = ReceiptIssueApprove.newBuilder();
		builder.setIssuerId(this.issuer.getIdAsString());
		builder.setRecepientId(this.recepient.getIdAsString());
		builder.setReceiptData(ByteString.copyFrom(this.receiptData));
		if(this.authProof == null) {
			throw new RuntimeException("cannot serialize this request without an authentication proof");
		}
		builder.setAuthenticationProof(this.authProof);
		return builder.build();
	}
	
}
