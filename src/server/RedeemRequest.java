package server;

import com.google.protobuf.ByteString;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ReceiptRedeemApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class RedeemRequest {
	
	private final Account issuer;
	private final Account owner;
	private final byte[] receiptHash;
	private final byte[] adsKey;
	private final byte[] currentValue;
	private final byte[] newValue;
	
	private MerklePrefixTrie authProof;
	
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
	
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}
	
	public MerklePrefixTrie getAuthenticationProof() {
		return this.authProof;
	}
	
	public ReceiptRedeemApprove serialize() {
		ReceiptRedeemApprove.Builder builder = ReceiptRedeemApprove.newBuilder();
		builder.setIssuerId(this.issuer.getIdAsString());
		builder.setOwnerId(this.owner.getIdAsString());
		builder.setReceiptHash(ByteString.copyFrom(this.receiptHash));
		if(this.authProof == null) {
			throw new RuntimeException("cannot serialize this request without an authentication proof");
		}
		builder.setAuthenticationProof(this.authProof);
		return builder.build();
	}
	
}
