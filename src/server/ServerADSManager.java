package server;

import java.util.List;

import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import mpt.dictionary.MPTDictionaryPartial;
import serialization.BVerifyAPIMessageSerialization.Updates;
import serialization.MptSerialization.MerklePrefixTrie;

public class ServerADSManager {
	
	private final String base;
	
	// current authentication information
	// over client ADSes
	private MPTDictionaryFull ads;
	
	// we also store the changes
	// TODO: consider if we want to store these 
	// or some subset of them on disk
	private List<MPTDictionaryDelta> deltas;
	
	public ServerADSManager(String base) {
		this.base = base;
		this.ads = new MPTDictionaryFull();
	}
	
	public void proposeChange(byte[] key, byte[] value) {
		
	}
	
	public byte[] commitChanges() {
		return null;
	}
	
	public byte[] get(byte[] key) {
		return this.ads.get(key);
	}
	
	public byte[] getProof(List<byte[]> keys) {
		MPTDictionaryPartial partial = new MPTDictionaryPartial(this.ads, keys);
		return partial.serialize().toByteArray();
	}
		
	public byte[] getUpdate(int startingCommitNumber, 
			List<byte[]> keyHashes) {
		Updates.Builder updates = Updates.newBuilder();
		// go through each commitment 
		for(int commitmentNumber = startingCommitNumber ; 
				commitmentNumber < this.deltas.size();
				commitmentNumber++) {
			// get the changes
			MPTDictionaryDelta delta = this.deltas.get(commitmentNumber);
			// and calculate the updates
			MerklePrefixTrie update = delta.getUpdates(keyHashes);
			updates.addUpdate(update);
		}
		return updates.build().toByteArray();
	}
	
}
