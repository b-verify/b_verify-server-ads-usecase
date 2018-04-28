package mock;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.github.javafaker.Faker;

import crpyto.CryptographicUtils;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryFull;
import mpt.set.MPTSetFull;
import pki.Account;
import pki.PKIDirectory;
import serialization.BVerifyAPIMessageSerialization.Receipt;

/**
 * This class is used to create mock data
 * for testing and demo purposes. All mock data 
 * is created in the /mock-data/ directory and 
 * can be read in using the MockClient class
 * to create mock clients.
 * @author henryaspegren
 *
 */
public class BootstrapMockSetup {
		
	public static void bootstrap(int nClient, int nWarehouses, int nReceipts, String base) {
		String pkiDirectoryFile  = base+"/pki/";
		String dataDirectoryFile = base+"/data/";
		String clientADSDirectoryFile = base+"/client-ads/";
		String serverADSDirectoryFile = base+"/server-ads/";
		
		int n = nWarehouses+nClient;
				
		// generate random accounts
		List<Account> accounts = PKIDirectory.generateRandomAccounts(n);
	    
	    //split into warehouses and depositors
	    List<Account> warehouses = accounts.subList(0, nWarehouses);
	    List<Account> depositors = accounts.subList(nWarehouses, n);
	    
	    // server auth 
	    MPTDictionaryFull serverADS = new MPTDictionaryFull();
	    
	    for(Account warehouse : warehouses) {
	    	for(Account depositor : depositors) {	    				    	
	    		List<Account> accs = new ArrayList<>();
	    		accs.add(warehouse);
	    		accs.add(depositor);
	    		// create an ADS to store 
	    		// receipts issued by this warehouse to this depositor
	    		byte[] adsKey = CryptographicUtils.listOfAccountsToADSKey(accs);
	    		String adsKeyString = Utils.byteArrayAsHexString(adsKey);
	    		MPTSetFull clientADS = new MPTSetFull();
		    	new File(dataDirectoryFile+adsKeyString).mkdirs();
		    	for(int i = 0; i < nReceipts; i++) {
	    			// create some receipts
	    			Receipt receipt = BootstrapMockSetup.generateReceipt(warehouse, depositor);
	    			byte[] witness = CryptographicUtils.witnessReceipt(receipt);
	    			// save the raw receipts in the data/adskey/ directory
	    			BootstrapMockSetup.saveReceipt(dataDirectoryFile+adsKeyString+"/"
	    					, receipt, witness);
	    			clientADS.insert(witness);
	    		}
	    		
		    	// save the client ads in the /client-ads/ directory
		    	BootstrapMockSetup.writeADSToFile(clientADSDirectoryFile, adsKey, clientADS.serialize().toByteArray());
		    	warehouse.addADSKey(adsKey);
		    	depositor.addADSKey(adsKey);
	    		byte[] adsRoot = clientADS.commitment();
	    		serverADS.insert(adsKey, adsRoot);
	    	}
	    }
	    
	    // save the accounts in the PKI directory
	    for(Account warehouse : warehouses) {
	    	warehouse.saveToFile(pkiDirectoryFile);
	    }
	    for(Account depositor : depositors) {
	    	depositor.saveToFile(pkiDirectoryFile);
	    }
	    
	    // save the server auth ADS in the server-ads directory
		BootstrapMockSetup.writeADSToFile(serverADSDirectoryFile, "starting-ads", serverADS.serialize().toByteArray());
	}
	
	
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
		String fileName = directory+Utils.byteArrayAsHexString(witness);
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(receipt.toByteArray());
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static Receipt loadReceipt(File receiptF) {
		try {
			FileInputStream fis = new FileInputStream(receiptF);
			byte[] encodedReceipt = new byte[(int) receiptF.length()];
			fis.read(encodedReceipt);
			fis.close();
			Receipt receipt = Receipt.parseFrom(encodedReceipt);
			return receipt;
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
	}
	
	public static void writeADSToFile(String directory, byte[] id, byte[] serializedADS) {
		String fileName = directory+Utils.byteArrayAsHexString(id);
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
		String fileName = directory+name;
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serializedADS);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static void main(String[] args) {
		
		// runs the bootstrap to setup the mock data
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/";
		BootstrapMockSetup.bootstrap(10, 1, 10, base);
	}
}
