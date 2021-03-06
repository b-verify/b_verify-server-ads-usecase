package server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;

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
	private ClientProvider rmi;
	
	/** 
	 * 	 Components
	 */
	private final BVerifyServerRequestVerifier verifier;
	private final BVerifyServerUpdateApplier applier;
	private final ExecutorService applierExecutor;
	
	/**
	 * Shared Data
	 */
	
	/*
	 * Lock is required for safety
	 */
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	
	/*
	 * ADS Manager used to update the authentication information
	 * stored on the server. 
	 */
	private final ADSManager adsManager;

	/*
	 * This is a shared queue using the producer-consumer 
	 * design pattern. This queue contains VERIFIED updates to be committed.
	 * Updates are added as they are verified and commitments are batched 
	 * for efficiency. 
	 */
	private BlockingQueue<PerformUpdateRequest> updatesToBeCommited;
		
	public BVerifyServer(String registryHost, int registryPort, StartingData initial, 
			int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, "staritng a b_verify server on host: "+registryHost+":"+registryPort+
				" (batch size: "+batchSize+" | require signatures: "+requireSignatures);
		this.pki = initial.getPKI();
		this.adsManager = new ADSManager(this.pki);
		this.updatesToBeCommited = new LinkedBlockingQueue<>();
		this.verifier = 
				new BVerifyServerRequestVerifier(this.lock, this.updatesToBeCommited, this.adsManager,
						requireSignatures);

		for(PerformUpdateRequest initializingUpdate : initial.getInitialUpdates()) {
			PerformUpdateResponse response;
			try {
				response = PerformUpdateResponse.parseFrom(
						this.verifier.performUpdate(initializingUpdate.toByteArray()));
			} catch (InvalidProtocolBufferException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
			boolean accepted = response.getAccepted();
			if(!accepted) {
				throw new RuntimeException("something wrong - initializing update rejected");
			}
		}
		// now start up the applier 
		// which will automatically apply the initializing updates 
		this.applier = new BVerifyServerUpdateApplier(this.lock,
						this.updatesToBeCommited, this.adsManager, batchSize);
		
		this.applierExecutor = Executors.newSingleThreadExecutor();
		this.applierExecutor.submit(this.applier);
		
		// now connect to the rmi
		this.rmi = new ClientProvider(registryHost, registryPort);
		
		BVerifyProtocolServerAPI serverAPI;
		try {
			// port 0 = any free port
			serverAPI = (BVerifyProtocolServerAPI) UnicastRemoteObject.exportObject(this.verifier, 0);
			this.rmi.bindServer(serverAPI);
			logger.log(Level.INFO, "... ready!");
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
		
	public BVerifyServer(StartingData initializingData, int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, "staritng a b_verify server in test mode (no RMI)"
				+ " (batch size: "+batchSize+" | require signatures: "+requireSignatures+")");
		this.pki = initializingData.getPKI();
		this.adsManager = new ADSManager(this.pki);
		this.updatesToBeCommited = new LinkedBlockingQueue<>();
		this.verifier = 
				new BVerifyServerRequestVerifier(this.lock, this.updatesToBeCommited, this.adsManager,
						requireSignatures);
		for(PerformUpdateRequest initializingUpdate : initializingData.getInitialUpdates()) {
			PerformUpdateResponse response;
			try {
				response = PerformUpdateResponse.parseFrom(
						this.verifier.performUpdate(initializingUpdate.toByteArray()));
			} catch (InvalidProtocolBufferException e) {
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
			}
			boolean accepted = response.getAccepted();
			if(!accepted) {
				throw new RuntimeException("something wrong - initializing update rejected");
			}
		}
		// now start up the applier 
		// which will automatically apply the initializing updates 
		this.applier = new BVerifyServerUpdateApplier(this.lock,
						this.updatesToBeCommited, this.adsManager, batchSize);
		
		this.applierExecutor = Executors.newSingleThreadExecutor();
		this.applierExecutor.submit(this.applier);
		
	} 
	
	public void shutdown() {
		logger.log(Level.INFO, "...shutting down the server");
		this.applier.setShutdown();
		this.applierExecutor.shutdown();
		try {
			this.applierExecutor.awaitTermination(10, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	// for testing only
	public BVerifyServerRequestVerifier getRequestHandler() {
		return this.verifier;
	}

}
