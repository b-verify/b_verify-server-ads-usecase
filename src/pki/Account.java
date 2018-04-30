package pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import crpyto.CryptographicSignature;

public class Account implements Serializable, Comparable<Account> {
	
	private static final long serialVersionUID = 1L;
	
	private final String firstName;
	private final String lastName;
	private final UUID id;
	private PublicKey pubKey;
	private PrivateKey privKey;
	
	// keeps track of the ADSes this client cares about
	// technically this does not need to be in the PKI, 
	// but to simplify things we store it here
	private Set<byte[]> adsKeys;
	
	public Account(String firstName, String lastName) {
		this.firstName = firstName;
		this.lastName = lastName;
		
		// generate a (unique) random id
		this.id = UUID.randomUUID();
		
		// along with pubKeys
		KeyPair keys = CryptographicSignature.generateNewKeyPair();
		this.pubKey = keys.getPublic();
		this.privKey = keys.getPrivate();
		
		this.adsKeys = new HashSet<>();
	}
	
	public void addADSKey(byte[] adsKey) {
		this.adsKeys.add(adsKey);
	}
	
	public Set<byte[]> getADSKeys(){
		return this.adsKeys;
	}
	
	public String getFirstName() {
		return this.firstName;
	}
	
	public String getLastName() {
		return this.lastName;
	}
	
	public PublicKey getPublicKey() {
		return pubKey;
	}
	
	public PrivateKey getPrivateKey() {
		return privKey;
	}
	
	public UUID getId() {
		return id;
	}
	
	public byte[] getIdAsBytes() {
		return id.toString().getBytes();
	}
	
	public String getIdAsString() {
		return id.toString();
	}
	
	public void saveToFile(String dir) {
		try {
			File f = new File(dir+id.toString());
			FileOutputStream fout = new FileOutputStream(f);
			ObjectOutputStream oos = new ObjectOutputStream(fout);
			oos.writeObject(this);
			oos.close();
			fout.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static Account loadFromFile(String file) {
		try {
			File f = new File(file);
			FileInputStream fin = new FileInputStream(f);
			ObjectInputStream ois = new ObjectInputStream(fin);
			Object obj = ois.readObject();
			ois.close();
			fin.close();
			Account account = (Account) obj;
			return account;
		}catch(Exception e) {
			return null;
		}	
	}
	
	public static Account loafFromFile(File f) {
		try {
			FileInputStream fin = new FileInputStream(f);
			ObjectInputStream ois = new ObjectInputStream(fin);
			Object obj = ois.readObject();
			ois.close();
			fin.close();
			Account account = (Account) obj;
			return account;
		}catch(Exception e) {
			return null;
		}	
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof Account) {
			Account a = (Account) obj;
			return this.id.equals(a.id);
		}
		return super.equals(obj);
	}
	
	@Override
	public String toString() {
		return "<"+this.id.toString()+">";
	}

	@Override
	public int compareTo(Account o) {
		return this.id.compareTo(o.id);
	}
	
}
