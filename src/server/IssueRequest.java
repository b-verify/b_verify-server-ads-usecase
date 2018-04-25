package server;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.Receipt;
import serialization.BVerifyAPIMessageSerialization.ReceiptIssueApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class IssueRequest implements Request {
	
	private final Account issuer;
	private final Account recepient;
	private final Receipt receipt;
	private final byte[] adsKey;
	private final byte[] newValue;
	
	private MerklePrefixTrie authProof;
	
	public IssueRequest(Account issuer, Account recepient,  
			Receipt receipt, byte[] adsKey,
			byte[] newValue) {
		this.issuer = issuer;
		this.recepient = recepient;
		this.receipt = receipt;
		this.adsKey = adsKey;
		this.newValue = newValue;
	}
		
	@Override
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}
	
	@Override
	public byte[] serialize() {
		ReceiptIssueApprove.Builder builder = ReceiptIssueApprove.newBuilder();
		builder.setIssuerId(this.issuer.getIdAsString());
		builder.setRecepientId(this.recepient.getIdAsString());
		builder.setReceipt(receipt);
		if(this.authProof == null) {
			throw new RuntimeException("cannot serialize this request without an authentication proof");
		}
		builder.setAuthenticationProof(this.authProof);
		return builder.build().toByteArray();
	}
	
	@Override
	public List<Account> sendRequestTo(){
		List<Account> sendTo = new ArrayList<>();
		sendTo.add(this.issuer);
		sendTo.add(this.recepient);
		return sendTo;
	}

	@Override
	public List<Map.Entry<byte[], byte[]>> getUpdatedKeyValues() {
		List<Map.Entry<byte[], byte[]>> kvtoadd = new ArrayList<>();
		kvtoadd.add(Map.entry(this.adsKey, this.newValue));
		return null;
	}
	
}
