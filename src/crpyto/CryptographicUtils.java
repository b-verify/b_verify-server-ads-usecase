package crpyto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import pki.Account;

/**
 * This class contains the various cryptographic 
 * commitments used by the rest of the library
 * @author henryaspegren
 *
 */
public class CryptographicUtils {

	/**
	 * Commits to a key and a value using the following commitment 
	 * 
	 * 					H(key||value)
	 * 
	 * @param key
	 * @param value
	 * @return
	 */
	public static byte[] witnessKeyAndValue(byte[] key, byte[] value) {
		byte[] witnessPreImage = new byte[key.length+value.length];
		System.arraycopy(key, 0, witnessPreImage, 0, key.length);
		System.arraycopy(value, 0, witnessPreImage, key.length, value.length);
		byte[] witness = CryptographicDigest.hash(witnessPreImage);
		return witness;
	}
	
	public static byte[] setOfAccountsToADSKey(Set<Account> accounts) {
		List<UUID> uuids = new ArrayList<>();
		for(Account a : accounts) {
			UUID id = a.getId();
			uuids.add(id);
		}
		// we canonically sort the accounts
		Collections.sort(uuids);
		
		// turn it into a list of byte arrays
		List<byte[]> preimage = new ArrayList<>();
		for(UUID id : uuids) {
			preimage.add(id.toString().getBytes());
		}
		
		// and take the sha256 hash of it all to get the key
		byte[] adsKey = CryptographicDigest.hash(preimage);
		
		return adsKey;
		
	}

}
