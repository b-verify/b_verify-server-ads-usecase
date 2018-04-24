package server;

import com.google.protobuf.ByteString;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.ReceiptTransferApprove;
import serialization.MptSerialization.MerklePrefixTrie;

public class TransferRequest {
	
	private final Account issuer;
	private final Account currentOwner;
	private final Account newOwner;
	private final byte[] receiptHash;
	private final byte[] currentOwnerAdsKey;
	private final byte[] newOwnerAdsKey;
	
	private final byte[] currentOwnerAdsValueOld;
	private final MerklePrefixTrie proofCurrentOwnerAdsOld;
	private final byte[] currentOwnerAdsValueNew;
	private final MerklePrefixTrie proofCurrentOwnerAdsNew;
	private final byte[] newOwnerAdsValueOld;
	private final MerklePrefixTrie proofNewOwnerAdsOld;
	private final byte[] newOwnerAdsValueNew;
	private final MerklePrefixTrie proofNewOwnerAdsNew;
	
	private MerklePrefixTrie authProof;
	
	
	public TransferRequest(Account issuer, Account currentOwner,
			Account newOwner, byte[] receiptHash, 
			byte[] currentOwnerAdsKey, byte[] newOwnerAdsKey,
			byte[] currentOwnerAdsValueOld,
			MerklePrefixTrie proofCurrentOwnerAdsOld,
			byte[] currentOwnerAdsValueNew,
			MerklePrefixTrie proofCurrentOwnerAdsNew,
			byte[] newOwnerAdsValueOld,
			MerklePrefixTrie proofNewOwnerAdsOld,
			byte[] newOwnerAdsValueNew,
			MerklePrefixTrie proofNewOwnerAdsNew) {
		
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


	public MerklePrefixTrie getProofCurrentOwnerAdsOld() {
		return proofCurrentOwnerAdsOld;
	}


	public byte[] getCurrentOwnerAdsValueNew() {
		return currentOwnerAdsValueNew;
	}


	public MerklePrefixTrie getProofCurrentOwnerAdsNew() {
		return proofCurrentOwnerAdsNew;
	}


	public byte[] getNewOwnerAdsValueOld() {
		return newOwnerAdsValueOld;
	}


	public MerklePrefixTrie getProofNewOwnerAdsOld() {
		return proofNewOwnerAdsOld;
	}


	public byte[] getNewOwnerAdsValueNew() {
		return newOwnerAdsValueNew;
	}


	public MerklePrefixTrie getProofNewOwnerAdsNew() {
		return proofNewOwnerAdsNew;
	}
	
	public void setAuthenticationProof(MerklePrefixTrie authProof) {
		this.authProof = authProof;
	}
	
	public MerklePrefixTrie getAuthenticationProof() {
		return this.authProof;
	}
	
	public ReceiptTransferApprove serialize() {
		ReceiptTransferApprove.Builder request = ReceiptTransferApprove.newBuilder();
		request.setIssuerId(ByteString.copyFrom(this.issuer.getIdAsBytes()));
		request.setCurrentOwnerId(ByteString.copyFrom(this.currentOwner.getIdAsBytes()));
		request.setNewOwnerId(ByteString.copyFrom(this.newOwner.getIdAsBytes()));
		request.setReceiptHash(ByteString.copyFrom(this.receiptHash));
		request.setOriginProof(this.proofCurrentOwnerAdsOld);
		request.setAddedProof(this.proofNewOwnerAdsNew);
		request.setRemovedProof(this.proofCurrentOwnerAdsNew);
		if(this.authProof == null) {
			throw new RuntimeException("tried to serialize a "
					+ "request without the authentication proof");
		}
		request.setAuthenticationProof(this.authProof);
		return request.build();
	}
	
}
