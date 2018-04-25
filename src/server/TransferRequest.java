package server;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.google.protobuf.ByteString;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ReceiptTransferApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class TransferRequest implements Request {
	
	private final Account issuer;
	private final Account currentOwner;
	private final Account newOwner;
	private final byte[] receiptHash;
	private final byte[] currentOwnerAdsKey;
	private final byte[] newOwnerAdsKey;
	
	private final MerklePrefixTrie proofCurrentOwnerAdsOld;
	private final byte[] currentOwnerAdsValueNew;
	private final MerklePrefixTrie proofCurrentOwnerAdsNew;
	private final byte[] newOwnerAdsValueNew;
	private final MerklePrefixTrie proofNewOwnerAdsNew;
	
	private MerklePrefixTrie authProof;
	
	
	public TransferRequest(Account issuer, Account currentOwner,
			Account newOwner, byte[] receiptHash, 
			byte[] currentOwnerAdsKey, byte[] newOwnerAdsKey,
			MerklePrefixTrie proofCurrentOwnerAdsOld,
			byte[] currentOwnerAdsValueNew,
			MerklePrefixTrie proofCurrentOwnerAdsNew,
			byte[] newOwnerAdsValueNew,
			MerklePrefixTrie proofNewOwnerAdsNew) {
		
		this.issuer = issuer;
		this.currentOwner = currentOwner;
		this.newOwner = newOwner;
		this.receiptHash = receiptHash;
		this.currentOwnerAdsKey = currentOwnerAdsKey;
		this.newOwnerAdsKey = newOwnerAdsKey;
		
		this.proofCurrentOwnerAdsOld = proofCurrentOwnerAdsOld;
		this.currentOwnerAdsValueNew = currentOwnerAdsValueNew;
		this.proofCurrentOwnerAdsNew = proofCurrentOwnerAdsNew;
		
		this.newOwnerAdsValueNew = newOwnerAdsValueNew;
		this.proofNewOwnerAdsNew = proofNewOwnerAdsNew;
		
	}
	
	@Override
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}
	
	@Override
	public List<Account> sendRequestTo(){
		List<Account> sendRequestTo = new ArrayList<Account>();
		sendRequestTo.add(this.issuer);
		sendRequestTo.add(this.currentOwner);
		sendRequestTo.add(this.newOwner);
		return sendRequestTo;
		
	}
	
	@Override
	public byte[] serialize() {
		ReceiptTransferApprove.Builder request = ReceiptTransferApprove.newBuilder();
		request.setIssuerId(this.issuer.getIdAsString());
		request.setCurrentOwnerId(this.currentOwner.getIdAsString());
		request.setNewOwnerId(this.newOwner.getIdAsString());
		request.setReceiptHash(ByteString.copyFrom(this.receiptHash));
		request.setOriginProof(this.proofCurrentOwnerAdsOld);
		request.setAddedProof(this.proofNewOwnerAdsNew);
		request.setRemovedProof(this.proofCurrentOwnerAdsNew);
		if(this.authProof == null) {
			throw new RuntimeException("tried to serialize a "
					+ "request without the authentication proof");
		}
		request.setAuthenticationProof(this.authProof);
		return request.build().toByteArray();
	}

	@Override
	public List<Entry<byte[], byte[]>> getUpdatedKeyValues() {
		List<Entry<byte[], byte[]>> updates = new ArrayList<>();
		updates.add(Map.entry(this.currentOwnerAdsKey, this.currentOwnerAdsValueNew));
		updates.add(Map.entry(this.newOwnerAdsKey, this.newOwnerAdsValueNew));
		return updates;
	}

	
	
}
