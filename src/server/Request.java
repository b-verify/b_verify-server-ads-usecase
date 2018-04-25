package server;

import java.util.List;
import java.util.Map;

import pki.Account;
import serialization.MptSerialization.MerklePrefixTrie;

public interface Request {
	
	public void setAuthenticationProof(MerklePrefixTrie authProof);
	
	public List<Map.Entry<byte[], byte[]>> getUpdatedKeyValues();

	public byte[] serialize();
	
	public List<Account> sendRequestTo();
}
