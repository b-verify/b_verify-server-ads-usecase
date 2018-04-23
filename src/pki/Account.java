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
import java.util.UUID;

import com.github.javafaker.Faker;

import crpyto.CryptographicSignature;

public class Account implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private final String firstName;
	private final String lastName;
	private final UUID id;
	private PublicKey pubKey;
	private PrivateKey privKey;
	
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
	
	public Account(String firstName, String lastName) {
		this.firstName = firstName;
		this.lastName = lastName;
		
		// generate a (unique) random id
		this.id = UUID.randomUUID();
		
		// along with pubkeys
		KeyPair keys = CryptographicSignature.generateNewKeyPair();
		this.pubKey = keys.getPublic();
		this.privKey = keys.getPrivate();
	}
	
	public void saveToFile(String path) {
		try {
			File f = new File(path+id.toString());
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
			throw new RuntimeException(e.getMessage());
		}	
	}
	
	public static void generateRandomAccounts(int numberOfAccounts, String base) {
		for(int i = 0; i < numberOfAccounts; i++) {
			Faker faker = new Faker();
			String firstName = faker.name().firstName(); 
			String lastName = faker.name().lastName(); 
			Account account = new Account(firstName, lastName);
			account.saveToFile(base);
			System.out.println("generating account "+(i+1)+
					" - of - "+numberOfAccounts+"("+faker.name().fullName()+")");
		}
	}
	
	public static void main(String[] args) {
		// generate 1k mock accounts
		Account.generateRandomAccounts(1000, 
				"/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/pki/");
	}
	
}
