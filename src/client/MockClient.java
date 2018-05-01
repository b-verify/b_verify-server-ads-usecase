package client;

import java.io.File;
import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import com.google.protobuf.ByteString;

import api.BVerifyProtocolClientAPI;
import crpyto.CryptographicSignature;
import mpt.core.Utils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;
import pki.Account;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.Signature;

/**
 * For benchmarking and testing purposes 
 * we include a mock implementation of a 
 * b_verify client.
 * 
 * This client checks proofs and automatically
 * approves all requests if the proofs are valid. 
 * Unlike a real client, this client 
 * does not initiate requests. Request
 * initiation will be controlled
 * by the benchmarking framework.
 * Additionally the benchmarking framework 
 * promises to send requests to the correct clients
 * to make the code on the mock client simpler.
 * 
 * @author henryaspegren
 *
 */
public class MockClient implements BVerifyProtocolClientAPI {
	
	// the account of this mock client
	private final Account account;

	// stores the full ADSes necessary for authenticating 
	// those receipts
	private final Map<byte[], AuthenticatedSetServer> receiptADSes;
	
	// provides rmi interface for 
	// invoking methods remotely on the server
	private ClientProvider rmi;
	
	public MockClient(Account a, String base) {
		this.account = a;
		this.receiptADSes = new HashMap<>();
		Set<byte[]> adsKeys = a.getADSKeys();
		for(byte[] adsKey : adsKeys) {
			AuthenticatedSetServer ads = MockClient
					.loadADSFromFile(base+"client-ads/", adsKey);
			this.receiptADSes.put(adsKey, ads);
		}
	}

	@Override
	public byte[] approveRequest(byte[] requestMessage) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean approveEchoBenchmark(boolean response) {
		System.out.println("Client "+this.account+ " echo request recieved, responding");
		return response;
	}
	
	@Override 
	public byte[] approveSigEchoBenchmark(byte[] toSign) {
		System.out.println("Client "+this.account+ " sig echo request recieved, responding");
		byte[] sigBytes = CryptographicSignature.sign(toSign, this.account.getPrivateKey());
		Signature.Builder sig = Signature.newBuilder();
		sig.setSignature(ByteString.copyFrom(sigBytes));
		return sig.build().toByteArray();
	}
	
	@Override 
	public String toString() {
		return "<"+this.account.getIdAsString()+" - "+this.receiptADSes.keySet()+">";
	}
	
	public void bind(String registryHost, int registryPort) {
		this.rmi = new ClientProvider(registryHost, registryPort);
		// bind this object
		BVerifyProtocolClientAPI clientAPI;
		try {
			clientAPI = (BVerifyProtocolClientAPI) UnicastRemoteObject.exportObject(this, 0);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
		this.rmi.bind(this.account.getIdAsString(), clientAPI);
	}
	
	public static AuthenticatedSetServer loadADSFromFile(String clientADSDir, 
			final byte[] adsKey) {
		File adsFile = new File(clientADSDir+Utils.byteArrayAsHexString(adsKey));
		try {
			FileInputStream fis = new FileInputStream(adsFile);
			byte[] encodedAds = new byte[(int) adsFile.length()];
			fis.read(encodedAds);
			fis.close();
			MPTSetFull mptSet = MPTSetFull.deserialize(encodedAds);
			return mptSet;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
	}
	
	public static void main(String[] args) {
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/";
		String host = null;
		int port = 1099;
		PKIDirectory pki = new PKIDirectory(base + "pki/");
		// create clients
		for(Account a : pki.getAllAccounts()) {
			// load client ads data
			MockClient mc = new MockClient(a, base);
			System.out.println(mc);
			mc.bind(host, port);
		}
		System.out.println("Press enter when test complete");
		Scanner sc = new Scanner(System.in);
		sc.nextLine();
		sc.close();
        System.out.println("Done!");
	}

}
