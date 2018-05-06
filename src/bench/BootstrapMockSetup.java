package bench;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import crpyto.CryptographicUtils;
import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryFull;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.Update;

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
	private static final Logger logger = Logger.getLogger(BootstrapMockSetup.class.getName());
	
	private static final String PKI_DIR = "pki/";
	private static final String SERVER_ADS_FILE = "server-ads";
	private static final String UPDATES_DIR = "updates/";
	
	public static void bootstrapSingleADSUpdates(String base, int nClients, int nTotalADSes, int nUpdates) {
	    // server auth 
	    MPTDictionaryFull serverADS = new MPTDictionaryFull();
	    
		// first generate a bunch of clients 
		List<Account> clients = PKIDirectory.generateRandomAccounts(nClients);
				
		// now create the correct number of ADSes
		// and updates
		List<PerformUpdateRequest> updates = new ArrayList<>();
		int adsNumber = 0;
		int updateNumber = 0;
		outer:
		for(int i = 0; i < clients.size(); i++) {
			for(int j = i+1; j < clients.size(); j++) {
				for(int k = j+1; k < clients.size(); k++) {
		       		if(adsNumber == nTotalADSes) {
		       			break outer;
		       		}
		       		adsNumber++;
					// make an ADS for these 3 clients 
					logger.log(Level.INFO, "...creating ads #"+adsNumber+" of "+nTotalADSes);
					Account a = clients.get(i);
					Account b = clients.get(j);
					Account c = clients.get(k);
					List<Account> accounts  = Arrays.asList(a, b, c);
					byte[] adsId = CryptographicUtils.listOfAccountsToADSId(accounts);
					a.addADSKey(adsId);
		       		b.addADSKey(adsId);
		       		c.addADSKey(adsId);
					byte[] adsRootOriginalValue = CryptographicDigest.hash((adsNumber+"START").getBytes());
		       		serverADS.insert(adsId, adsRootOriginalValue);
		       		
		       		// make an update if necessary
		       		if(updateNumber < nUpdates) {
			    		updateNumber++;
						byte[] adsRootUpdatedValue = CryptographicDigest.hash((adsNumber+"START").getBytes());
						logger.log(Level.INFO, "...generating update #"+updateNumber+" of "+nUpdates);
			    		ADSModification modification = ADSModification.newBuilder()
			    				.setAdsId(ByteString.copyFrom(adsId))
			    				.setNewValue(ByteString.copyFrom(adsRootUpdatedValue))
			    				.build();
			    		Update update = Update.newBuilder()
			    				.addModifications(modification)
			    				.build();
			    		PerformUpdateRequest request  = produceUpdateRequest(update, accounts);
			    		updates.add(request);
		       		}
				}
			}
		}
		if(adsNumber != nTotalADSes || updateNumber != nUpdates) {
			throw new RuntimeException("not enough clients provided!");
		}
		logger.log(Level.INFO, "...done generating ADSes and Updates!");
		logger.log(Level.INFO, "...saving the clients");
		for(Account client : clients) {
			saveClient(base, client);
		}
		logger.log(Level.INFO, "...saving the server ads");
		saveServerADS(base, serverADS);
		logger.log(Level.INFO, "...saving the update requests");
		savePerformUpdateRequests(base, updates);		
	}
			
	public static void bootstrapSingleADSPerClient(String base, int nClients) {

	    // server auth 
	    MPTDictionaryFull serverADS = new MPTDictionaryFull();
	    
	    // generate a bunch of clients
		List<Account> clients = PKIDirectory.generateRandomAccounts(nClients);
		
		// generate one update per client
		List<PerformUpdateRequest> updateRequests = new ArrayList<>();
		for(Account client : clients) {
			byte[] adsId = CryptographicUtils.listOfAccountsToADSId(Arrays.asList(client));
			String adsIdString  = Utils.byteArrayAsHexString(adsId);
			logger.log(Level.INFO, "...creating "+client+" with ads_id "+adsIdString);
						
			logger.log(Level.INFO, "...generating starting value");
			byte[] adsRootOriginalValue = CryptographicDigest.hash((client.getIdAsBytes()+"START").getBytes());
       		serverADS.insert(adsId, adsRootOriginalValue);

			logger.log(Level.INFO, "...generating updated value");
			byte[] adsRootUpdatedValue = CryptographicDigest.hash((client.getIdAsBytes()+"END").getBytes());
			
			logger.log(Level.INFO, "...generating update request");
    		ADSModification modification = ADSModification.newBuilder()
    				.setAdsId(ByteString.copyFrom(adsId))
    				.setNewValue(ByteString.copyFrom(adsRootUpdatedValue))
    				.build();
    		
    		Update update = Update.newBuilder()
    				.addModifications(modification)
    				.build();
    		
    		byte[] witness = CryptographicDigest.hash(update.toByteArray());
    		byte[] signature = CryptographicSignature.sign(witness, client.getPrivateKey());
    		
    		PerformUpdateRequest request = PerformUpdateRequest.newBuilder()
    				.setUpdate(update)
    				.addSignatures(ByteString.copyFrom(signature))
    				.build();
    		
    		updateRequests.add(request);
    		
    		client.addADSKey(adsId);
			saveClient(base, client);
		}
		
		logger.log(Level.INFO, "...saving the server ads");
		saveServerADS(base, serverADS);
		
		logger.log(Level.INFO, "...saving the update requests");
		savePerformUpdateRequests(base, updateRequests);
	}
	
	
	public static PerformUpdateRequest produceUpdateRequest(Update update, List<Account> accounts) {
		// calculate the witness
		byte[] witness = CryptographicDigest.hash(update.toByteArray());
		
		// have the account sign in order!
		Collections.sort(accounts);
  		PerformUpdateRequest.Builder request = PerformUpdateRequest.newBuilder()
				.setUpdate(update);
  		for(Account a : accounts) {
  			byte[] signature = CryptographicSignature.sign(witness, a.getPrivateKey());
  			request.addSignatures(ByteString.copyFrom(signature));
  		}
		return request.build();
		
	}
	
	public static void savePerformUpdateRequests(String base, List<PerformUpdateRequest> requests) {
		String directory = base + UPDATES_DIR;
		int i = 0;
		for(PerformUpdateRequest request : requests) {
			File f = new File(directory+i);
			writeBytesToFile(f, request.toByteArray());
			i++;
		}
	}
	
	public static List<PerformUpdateRequest> loadPerformUpdateRequests(String base){
		String directory = base+UPDATES_DIR;
		File dir = new File(directory);
		File[] files = dir.listFiles();
		List<PerformUpdateRequest> requests = new ArrayList<>();
		for(File f : files) {
			byte[] request  = readBytesFromFile(f);
			try {
				requests.add(PerformUpdateRequest.parseFrom(request));
			} catch (InvalidProtocolBufferException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
		}
		return requests;
	}
	
	public static void saveClient(String base, Account client) {
		client.saveToFile(base+PKI_DIR);
	}


	public static void saveServerADS(String base, MPTDictionaryFull mpt) {
		File f = new File(base+ SERVER_ADS_FILE);
		writeBytesToFile(f, mpt.serialize().toByteArray());
	}
	
	public static MPTDictionaryFull loadServerADS(String base) {
		File f = new File(base+SERVER_ADS_FILE);
		byte[] asBytes = readBytesFromFile(f);
		try {
			MPTDictionaryFull mpt =  MPTDictionaryFull.deserialize(asBytes);
			return mpt;
		} catch (InvalidSerializationException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	public static void resetDataDir(String base) {
		// delete the old test data
		try {
			FileUtils.deleteDirectory(new File(base));
			new File(base).mkdirs();
			new File(base+PKI_DIR).mkdirs();
			new File(base+UPDATES_DIR).mkdirs();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		// create new directories
	}
	
	public static void writeBytesToFile(File f, byte[] toWrite) {
		try {
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(toWrite);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static byte[] readBytesFromFile(File f) {
		try {
			FileInputStream fis = new FileInputStream(f);
			byte[] data = new byte[(int) f.length()];
			fis.read(data);
			fis.close();
			return data;
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
	}

}
