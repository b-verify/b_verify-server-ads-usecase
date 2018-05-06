package server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import api.BVerifyProtocolServerAPI;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;

public class BVerifyServer {
	private static final Logger logger = Logger.getLogger(BVerifyServer.class.getName());
	
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
	private BlockingQueue<PerformUpdateRequest> updatesToBeCommited;
	
	
	
	/**
	 * 			MISC
	 */
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public BVerifyServer(String base, String registryHost, int registryPort, int batchSize) {
		this.pki = new PKIDirectory(base + "pki/");
		logger.log(Level.INFO, "... loaded pki");
		this.rmi = new ClientProvider(registryHost, registryPort);
		logger.log(Level.INFO, "... loaded rmi");

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
		BVerifyServerRequestHandler verifierForRMI = 
				new BVerifyServerRequestHandler(this.updatesToBeCommited, this.adsManager);
		BVerifyProtocolServerAPI serverAPI;
		try {
			// port 0 = any free port
			logger.log(Level.INFO, "... binding server on port: "+registryPort);
			serverAPI = (BVerifyProtocolServerAPI) UnicastRemoteObject.exportObject(verifierForRMI, 0);
			this.rmi.bindServer(serverAPI);
			logger.log(Level.INFO, "... ready!");
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
}
