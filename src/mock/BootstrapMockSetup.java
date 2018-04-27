package mock;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;

import com.github.javafaker.Faker;

import crpyto.CryptographicUtils;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryFull;
import mpt.set.MPTSetFull;
import pki.Account;
import pki.PKIDirectory;
import serialization.BVerifyAPIMessageSerialization.Receipt;

public class BootstrapMockSetup {

	/**
	 * Used to generate fake but vaguely realistic data
	 */
	private static Faker FAKER = new Faker();
	
	public static Receipt generateReceipt(Account issuer, Account recepient) {
		Receipt.Builder rec = Receipt.newBuilder();
		rec.setWarehouseId(issuer.getIdAsString());
		rec.setDepositorId(recepient.getIdAsString());
		rec.setAccountant(FAKER.name().name());
		rec.setCategory(FAKER.yoda().quote());
		Date now = new Date();
		rec.setDate(now.toString());
		rec.setInsurance("");
		rec.setWeight(FAKER.number().randomDouble(2, 0, 1000));
		rec.setVolume(FAKER.number().randomDouble(2, 0, 1000));
		rec.setHumidity(FAKER.number().randomDouble(3, 0, 1));
		rec.setPrice(FAKER.number().randomDouble(2, 1000, 10000));
		rec.setDetails(""+FAKER.number().randomNumber());
		return rec.build();
	}
	
	public static void saveReceipt(String directory, Receipt receipt, byte[] witness) {
		String fileName = directory+"/"+Utils.byteArrayAsHexString(witness);
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(receipt.toByteArray());
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static void writeADSToFile(String directory, byte[] id, byte[] serializedADS) {
		String fileName = directory+"/"+Utils.byteArrayAsHexString(id);
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serializedADS);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	
	public static void writeADSToFile(String directory, String name, byte[] serializedADS) {
		String fileName = directory+"/"+name;
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serializedADS);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
		
	public static boolean bootstrap(int nClient, int nWarehouses, int nReceipts, String base) {
		String pkiDirectoryFile  = base+"/pki/";
		String dataDiectoryFile = base+"/data/";
		String clientADSDirectoryFile = base+"/client-ads/";
		String serverADSDirectoryFile = base+"/server-ads/";
		
		int n = nWarehouses+nClient;
		
		// generate the accounts
		PKIDirectory.generateRandomAccounts(n, pkiDirectoryFile);
		PKIDirectory pki = new PKIDirectory(pkiDirectoryFile);
		Set<Account> accounts = pki.getAllAccounts();
	    List<Account> accountsList = new ArrayList<>();
	    accountsList.addAll(accounts);
	    
	    //split into warehouses and depositors
	    List<Account> warehouses = accountsList.subList(0, nWarehouses);
	    List<Account> depositors = accountsList.subList(nWarehouses, n);
	    
	    // server auth 
	    MPTDictionaryFull serverADS = new MPTDictionaryFull();
	    
	    for(Account warehouse : warehouses) {
	    	// create a warehouse directory
	    	String dataDirectory  = dataDiectoryFile+warehouse.getIdAsString();
	    	new File(dataDirectory).mkdirs();
	    	
	    	for(Account depositor : depositors) {
	    		// for each depositor create a directory
	    		String depositorDirectory = dataDirectory+"/"+depositor.getIdAsString();
		    	new File(depositorDirectory).mkdirs();
	    				    	
		    	// create ADS
	    		List<Account> accs = new ArrayList<>();
	    		accs.add(warehouse);
	    		accs.add(depositor);
	    		byte[] adsKey = CryptographicUtils.listOfAccountsToADSKey(accs);
	    		MPTSetFull clientADS = new MPTSetFull();
	    		
	    		for(int i = 0; i < nReceipts; i++) {
	    			// create receipt
	    			Receipt receipt = BootstrapMockSetup.generateReceipt(warehouse, depositor);
	    			// save receipt in data folder
	    			byte[] witness = CryptographicUtils.witnessReceipt(receipt);
	    			BootstrapMockSetup.saveReceipt(depositorDirectory, receipt, witness);
	    			// and put the witness in the ADS
	    			clientADS.insert(witness);
	    		}
	    		// save the client ads 
	    		BootstrapMockSetup.writeADSToFile(clientADSDirectoryFile, adsKey, clientADS.serialize().toByteArray());
	    		byte[] adsRoot = clientADS.commitment();
	    		serverADS.insert(adsKey, adsRoot);
	    	}
	    }
	    
	    // save the server auth ads
		BootstrapMockSetup.writeADSToFile(serverADSDirectoryFile, "starting-ads", serverADS.serialize());

		return false;
	}
	
	
	public static void main(String[] args) {
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/";
		BootstrapMockSetup.bootstrap(10, 1, 10, base);
	}
}
