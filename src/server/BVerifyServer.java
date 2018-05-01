package server;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import api.BVerifyProtocolClientAPI;
import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicSignature;
import pki.Account;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.Signature;

public class BVerifyServer {
	
	/*
	 * Public Key Infrastructure - for identifying clients. For now this is mocked,
	 * but there are a variety of different possible ways to implement this.
	 */
	private final PKIDirectory pki;

	/*
	 * RMI (or other RPC framework) for sending requests
	 */
	private final ClientProvider rmi;
	
	/** 
	 * 			SHARED DATA
	 */
	
	/*
	 * ADS Manager used to update the authentication information
	 * stored on the server. 
	 */
	protected final ADSManager adsManager;

	/*
	 * This is a shared queue using the producer-consumer 
	 * design pattern. This queue contains VERIFIED updates to be committed.
	 * Updates are added as they are verified and commitments are batched 
	 * for efficiency. 
	 */
	private BlockingQueue<Update> updatesToBeCommited;
	
	
	
	/**
	 * 			MISC
	 */
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public BVerifyServer(String base, String registryHost, int registryPort, int batchSize) {
		this.pki = new PKIDirectory(base + "pki/");
		System.out.println("loaded PKI");
		this.rmi = new ClientProvider(registryHost, registryPort);
		
		// setup the shared data
		this.adsManager = new ADSManager(base, this.pki);
		this.updatesToBeCommited = new LinkedBlockingQueue<>();

		// setup the components 
		
		// this component runs as its own thread
		BVerifyServerUpdateApplier applierThread = 
				new BVerifyServerUpdateApplier(this.updatesToBeCommited, this.adsManager, batchSize);
		applierThread.start();
		
		// this is an object exposed to the RMI interface.
		// the RMI library handles the threading and 
		// may invoke multiple methods concurrently on this 
		// object
		BVerifyServerRequestVerifier verifierForRMI = 
				new BVerifyServerRequestVerifier(this.updatesToBeCommited, this.adsManager);
		BVerifyProtocolServerAPI serverAPI;
		try {
			// port 0 = any free port
			serverAPI = (BVerifyProtocolServerAPI) UnicastRemoteObject.exportObject(verifierForRMI, 0);
			this.rmi.bindServer(serverAPI);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}

	public boolean benchmarkEcho() {
		Collection<Callable<Boolean>> approvals = new ArrayList<Callable<Boolean>>();
		for(Account a : this.pki.getAllAccounts()) {
			approvals.add(new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					System.out.println("Making call to client: "+a);
					BVerifyProtocolClientAPI stub = rmi.getClient(a);
					Boolean resp = Boolean.valueOf(stub.approveEchoBenchmark(true));
					System.out.println("Response from client: "+a+" - "+resp);
					return resp;
				}
				
			});
		}
		boolean commit = true;
		try {
			List<Future<Boolean>> results = WORKERS.invokeAll(approvals, TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : results) {
				Boolean resultBool = result.get();
				commit = commit && resultBool.booleanValue();
			}
		} catch (InterruptedException | ExecutionException e) {
			commit = false;
			e.printStackTrace();
		}
		System.out.println("DONE PROCESSING RESPONSES RESULT: "+commit);
		return commit;
	}
	
	public boolean benchmarkSigEcho() {
		Collection<Callable<Boolean>> approvals = new ArrayList<Callable<Boolean>>();
		for(Account a : this.pki.getAllAccounts()) {
			approvals.add(new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					System.out.println("Making call to client: "+a);
					BVerifyProtocolClientAPI stub = rmi.getClient(a);
					byte[] message = "some message".getBytes();
					byte[] resp = stub.approveSigEchoBenchmark(message);
					Signature sig = Signature.parseFrom(resp);
					System.out.println("Response from client: "+a+" signature - "+sig);
					boolean valid = CryptographicSignature.verify(message, 
							sig.getSignature().toByteArray(), a.getPublicKey());
					System.out.println("Response from client: "+a+" signature valid? - "+valid);
					return Boolean.valueOf(valid);
				}
				
			});
		}
		boolean commit = true;
		try {
			List<Future<Boolean>> results = WORKERS.invokeAll(approvals, TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : results) {
				Boolean resultBool = result.get();
				commit = commit && resultBool.booleanValue();
			}
		} catch (InterruptedException | ExecutionException e) {
			commit = false;
			e.printStackTrace();
		}
		System.out.println("DONE PROCESSING RESPONSES RESULT: "+commit);
		return commit;
	}
	
	
	
	public static void main(String[] args) throws RemoteException {
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/";
		String host = null;
		int port = 1099;
		int batchSize = 1;
		// first create a registry
		LocateRegistry.createRegistry(port);
		
		BVerifyServer server = new BVerifyServer(base, host, port, batchSize);
		@SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in);
		while(true) {
			System.out.println("Press enter to start test");
			sc.nextLine();
	        System.out.println("Starting test");
	        boolean res = server.benchmarkSigEcho();
	        System.out.println("Test complete - res: "+res);
		}
	}
	

}
