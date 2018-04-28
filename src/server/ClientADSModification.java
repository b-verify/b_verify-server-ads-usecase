package server;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import pki.Account;

public class ClientADSModification {

	private final Set<byte[]> elementsToInsert;
	private final Set<byte[]> elementsToDelete;
	
	private final byte[] adsKey;
	private final byte[] adsValue;
	
	private final Map<Account, byte[]> approvalSignatures;
	
	public ClientADSModification(byte[] adsKey, byte[] adsValue,
			Set<Account> approval, Set<byte[]> inserts, Set<byte[]> deletes) {
		this.adsKey = adsKey;
		this.adsValue = adsValue;
		this.elementsToInsert = inserts;
		this.elementsToDelete = deletes;
		this.approvalSignatures = new HashMap<>();
		for(Account a : approval) {
			this.approvalSignatures.put(a, null);
		}
	}
	
	public void addApproval(Account a, byte[] sig) {
		if(!this.approvalSignatures.containsKey(a)) {
			throw new RuntimeException("adding approval for an irrelevant account");
		}
		this.approvalSignatures.put(a, sig);
	}
	
	public byte[] getADSKey() {
		return this.adsKey;
	}
	
	public byte[] getADSValue() {
		return this.adsValue;
	}
	
	public Set<byte[]> getInserts(){
		return this.elementsToInsert;
	}
	
	public Set<byte[]> getDeletes(){
		return this.elementsToDelete;
	}
	
	
	
}
