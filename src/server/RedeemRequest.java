package server;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.google.protobuf.ByteString;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ReceiptRedeemApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class RedeemRequest implements Request {
	
	private final Account issuer;
	private final Account owner;
	private final byte[] receiptHash;
	private final byte[] adsKey;
	private final byte[] newValue;
	
	private MerklePrefixTrie authProof;
	
	public RedeemRequest(Account issuer, Account owner,
			byte[] receiptHash, byte[] adsKey,
			byte[] newValue) {
		this.issuer = issuer;
		this.owner = owner;
		this.receiptHash = receiptHash;
		this.adsKey = adsKey;
		this.newValue = newValue;
	}
	
	@Override
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}

	@Override
	public byte[] serialize() {
		ReceiptRedeemApprove.Builder builder = ReceiptRedeemApprove.newBuilder();
		builder.setIssuerId(this.issuer.getIdAsString());
		builder.setOwnerId(this.owner.getIdAsString());
		builder.setReceiptHash(ByteString.copyFrom(this.receiptHash));
		if(this.authProof == null) {
			throw new RuntimeException("cannot serialize this request without an authentication proof");
		}
		builder.setAuthenticationProof(this.authProof);
		return builder.build().toByteArray();
	}

	@Override
	public List<Account> sendRequestTo() {
		List<Account> sendTo = new ArrayList<>();
		sendTo.add(this.issuer);
		sendTo.add(this.owner);
		return null;
	}

	@Override
	public List<Entry<byte[], byte[]>> getUpdatedKeyValues() {
		List<Entry<byte[], byte[]>> updates = new ArrayList<>();
		updates.add(Map.entry(this.adsKey, this.newValue));
		return updates;
	}
	
}
