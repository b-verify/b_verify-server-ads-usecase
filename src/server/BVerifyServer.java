package server;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolClientAPI;
import api.BVerifyProtocolServerAPI;
import crpyto.CryptographicSignature;
import crpyto.CryptographicUtils;
import mpt.set.MPTSetFull;
import mpt.set.MPTSetPartial;
import pki.Account;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.BVerifyAPIMessageSerialization.ADSModification;
import serialization.BVerifyAPIMessageSerialization.GetUpdatesRequest;
import serialization.BVerifyAPIMessageSerialization.Request;
import serialization.BVerifyAPIMessageSerialization.Signature;
import serialization.MptSerialization.MerklePrefixTrie;

public class BVerifyServer implements BVerifyProtocolServerAPI {
	
	/**
	 * Public Key Infrastructure - for identifying clients. For now this is mocked,
	 * but there are a variety of different possible ways to implement this.
	 */
	protected final PKIDirectory pki;

	/**
	 * RMI (or other RPC framework) for sending requests
	 */
	protected final ClientProvider rmi;
	
	/**
	 * Client ADSes
	 */
	protected final ClientADSManager clientadsManager;

	/**
	 * Server (Authentication) ADSes
	 */
	protected final ServerADSManager serveradsManager;
	
	/**
	 * When ADSes are updated, the server will request
	 * signatures from the required parties
	 */
	private Set<Update> updatesToBeAttempted;
	
	/**
	 * Once a request has been signed by all parties
	 * it is added to this set to be applied at a later point.
	 * Changes are batched and committed together for 
	 * efficiency.
	 */
	private Set<Update> updatesToBeApplied;
	
	/**
	 * We use read-write locks to handle concurrent client requests 
	 * from the server
	 */
	protected final ReadWriteLock rwLock = new ReentrantReadWriteLock();
	
	/**
	 * Also we may need to make requests to multiple clients 
	 * and these requests should be done in parallel
	 */
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public BVerifyServer(String base, String registryHost, int registryPort) {
		this.pki = new PKIDirectory(base + "/pki/");
		this.rmi = new ClientProvider(registryHost, registryPort);
		// bind this object
		BVerifyProtocolServerAPI serverAPI;
		try {
			// port 0 = any free port
			serverAPI = (BVerifyProtocolServerAPI) UnicastRemoteObject.exportObject(this, 0);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
		this.rmi.bind(ClientProvider.SERVER_NAME, serverAPI);
		
		this.clientadsManager = new ClientADSManager(this.pki, base + "/client-ads/");
		this.serveradsManager = new ServerADSManager(base + "/server-ads/");	
		
		this.updatesToBeAttempted = new HashSet<>();
		this.updatesToBeApplied = new HashSet<>();
	}

	@Override
	public boolean submitRequest(byte[] requestMessage) {
		try {
			// #1 parse the request message
			Request request = Request.parseFrom(requestMessage);
			Account requestInitiator = this.pki.getAccount(request.getRequestInitiatorId());
						
			// #2 look up all the ads modifications required by this request
			Set<ClientADSModification> modifications = new HashSet<>();
			for(ADSModification adsModifcation : request.getModificationsList()) {
				byte[] adsKey = adsModifcation.getAdsId().toByteArray();
				byte[] adsValue = adsModifcation.getNewValue().toByteArray();
				Set<Account> relevantAccounts = 
						this.clientadsManager.getRelevantClients(adsKey);
				ClientADSModification adsModification = 
						new ClientADSModification(adsKey, adsValue, 
								relevantAccounts, null, null);
				// #3 make sure that the request initiator has signed 
				// any relevant
				if(relevantAccounts.contains(requestInitiator)) {
					byte[] signature = adsModifcation.getSignature().toByteArray();
					boolean signed = CryptographicSignature.verify(adsValue, signature,
							requestInitiator.getPublicKey());
					adsModification.addApproval(requestInitiator, signature);
					if(!signed) {
						return false;
					}
				}
				modifications.add(adsModification);
			}
			
			// #4 request signatures from any other parties
			relevantAccounts.remove(requestInitiator);
			Update requestForSig = new Update(relevantAccounts, request);
			this.updatesToBeAttempted.add(requestForSig);
			return true;
		} 	catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			
			this.rwLock.readLock().unlock();
			return false;
		}
	}


	@Override
	public byte[] getUpdates(byte[] updateRequest) {
		try {
			this.rwLock.readLock().lock();
			GetUpdatesRequest request = GetUpdatesRequest.parseFrom(updateRequest);
			// parse the keys
			List<byte[]> keys = new ArrayList<>();
			List<ByteString> keyByteStrings = request.getKeysList();
			for (ByteString key : keyByteStrings) {
				keys.add(key.toByteArray());
			}
			int from = request.getFromCommitNumber();
			this.rwLock.readLock().unlock();
			return this.serveradsManager.getUpdate(from, keys);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
			this.rwLock.readLock().unlock();
			return null;
		}
	}

	public boolean commitUpdates() {
		this.rwLock.writeLock().lock();
		// apply the updates
		for(Update updateReq : this.updatesToBeApplied) {
			// for now just update the server
			// authentication table
			for(Map.Entry<byte[], byte[]> update : updateReq.getUpdatedKeyValues()) {
				this.serveradsManager.update(update.getKey(), update.getValue());
			}
		}
		this.updatesToBeApplied.clear();
		this.rwLock.writeLock().unlock();
		return true;
	}
		
	
	public boolean requestSig() {
		// send proofs and wait to collect the signature
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
		if(commit) {
			this.serveradsManager.commit();
			this.clientadsManager.commit();
			this.rwLock.writeLock().unlock();
			return true;
		}
		this.serveradsManager.abort();
		this.clientadsManager.abort();
		this.rwLock.writeLock().lock();
		return false;
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
		// first create a registry
		LocateRegistry.createRegistry(port);
		
		BVerifyServer server = new BVerifyServer(base, host, port);
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
