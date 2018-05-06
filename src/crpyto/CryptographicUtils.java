package crpyto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import pki.Account;

/**
 * This class contains the various cryptographic commitments and mappings used
 * by the b_verify protocol
 * 
 * @author henryaspegren
 *
 */
public class CryptographicUtils {

	/**
	 * Commits to a key and a value using the following commitment
	 * 
	 * H(key||value)
	 * 
	 * @param key
	 * @param value
	 * @return
	 */
	public static byte[] witnessKeyAndValue(byte[] key, byte[] value) {
		byte[] witnessPreImage = new byte[key.length + value.length];
		System.arraycopy(key, 0, witnessPreImage, 0, key.length);
		System.arraycopy(value, 0, witnessPreImage, key.length, value.length);
		byte[] witness = CryptographicDigest.hash(witnessPreImage);
		return witness;
	}
	
	/**
	 * TODO - need to finalize what this will look like
	 * 
	 * Used to calculate the witness for a server update
	 * 
	 * @param authRoot
	 *            - the root of the authentication ADS, required in case of
	 *            coordinating commits across multiple ADSes.
	 * @return
	 */
	public static byte[] witnessUpdate(byte[] authRoot) {
		byte[] witness = CryptographicDigest.hash(authRoot);
		return witness;
	}
	
	/**
	 * This method provides a deterministic mapping from a list of accounts to an
	 * ADS_ID, returning a unique cryptographic identifier for the ADS
	 * 
	 * @param accounts
	 *            - the list of (unique) accounts
	 * @return a fixed-length unique identifier for the ADS (the "ADS Key"). This
	 *         can be used to lookup the ADS and as a cryptographic commitment to
	 *         that ADS.
	 */
	public static byte[] listOfAccountsToADSId(List<Account> accounts) {
		Collections.sort(accounts);
		
		// turn it into a list of byte arrays
		List<byte[]> preimage = new ArrayList<>();
		for (Account account : accounts) {
			preimage.add(account.getIdAsBytes());
		}

		// and take the sha256 hash of it all to get the key
		byte[] adsKey = CryptographicDigest.hash(preimage);
		return adsKey;
	}

}
