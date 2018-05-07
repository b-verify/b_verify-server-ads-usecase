package bench;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import mpt.dictionary.MPTDictionaryPartial;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateResponse;
import serialization.generated.BVerifyAPIMessageSerialization.ProveUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveUpdateResponse;
import server.BVerifyServer;

public class ServerSingleUpdateBaselineThroughputBenchmark {
	private static final Logger logger = Logger.getLogger(ServerSingleUpdateBaselineThroughputBenchmark.class.getName());
	
	private static final int NUMBER_OF_THREADS = 2000;
	private static final int TOTAL_TASK_TIMEOUT = 30;
	
	private static final ThreadPoolExecutor WORKERS = 
			new ThreadPoolExecutor(NUMBER_OF_THREADS, // keep these threads alive even if idle
								   NUMBER_OF_THREADS, // total size of thread pool
								   30, // idle timeout
								    TimeUnit.SECONDS,
								    // can also queue up to 10k tasks
								    new ArrayBlockingQueue<Runnable>(10000));
	
	private static final int MILLISECONDS_OF_RANDOM_DELAY = 5000;
		
	/*
	 * Run this once to generate the data for the benchmark
	 */
	public static void generateTestData(String base, int nClients, int nTotalADSes, int nUpdates) {
		logger.log(Level.INFO, "...resetting the test data");
		BootstrapMockSetup.resetDataDir(base);
		logger.log(Level.INFO, "...generating test data for simple throughput benchmark");
		BootstrapMockSetup.bootstrapSingleADSUpdates(base, nClients, nTotalADSes, nUpdates);	
	}
	
	public static void runBenchmarkServer(String base, String host, int port, int batchSize) {
		logger.log(Level.INFO, "...starting server on host: "+host+" port: "+port);
		// first create a registry on localhost
		try {
			if(host != null) {
				 System.setProperty("java.rmi.server.hostname", host);
			}
			LocateRegistry.createRegistry(port);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		
		// start up the server (also on localhost)
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(base, null, port, batchSize);
		logger.log(Level.INFO, "...ready!");
		Scanner sc = new Scanner(System.in);
		logger.log(Level.INFO, "[Press enter to kill sever]");
		sc.nextLine();
		sc.close();
	}
	
	public static void runBenchmarkClients(String base, String host, int port) {
		logger.log(Level.INFO, "...creating mock clients connected to b_verify server \n "
				+ "on host: "+host+" port: "+port);
		// first connect to the registry 
		ClientProvider rmi = new ClientProvider(host, port);

		// now throw requests at it
		List<PerformUpdateRequest> requests = BootstrapMockSetup.loadPerformUpdateRequests(base);
		
		Collection<Callable<Boolean>> makeUpdateRequestWorkers = new ArrayList<Callable<Boolean>>();
		Collection<Callable<Boolean>> verifyUpdatePerformedWorkers = new ArrayList<Callable<Boolean>>();
		
		for(PerformUpdateRequest request : requests) {
			// for now only one ADS Modification per request
			ADSModification singleModification = request.getUpdate().getModifications(0);
			byte[] adsId = singleModification.getAdsId().toByteArray();
			byte[] newAdsRoot = singleModification.getNewValue().toByteArray();
			
			// construct the proof request
			ProveUpdateRequest proofRequest = ProveUpdateRequest.newBuilder()
					.addAdsIds(singleModification.getAdsId())
					.build();
			
			byte[] updateRequestAsBytes = request.toByteArray();
			byte[] proofRequestAsBytes = proofRequest.toByteArray();
			
			
			makeUpdateRequestWorkers.add(new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						// request the update
						Random rand = new Random();
						Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
						byte[] responseBytes = rmi.getServer().performUpdate(updateRequestAsBytes);
						PerformUpdateResponse response = PerformUpdateResponse.parseFrom(responseBytes);
						return Boolean.valueOf(response.getAccepted());
					}
				});
			
			verifyUpdatePerformedWorkers.add(new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					// ask for a proof it was applied 
					Random rand = new Random();
					Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
					byte[] proofApplied = rmi.getServer().proveUpdate(proofRequestAsBytes);
					ProveUpdateResponse up = ProveUpdateResponse.parseFrom(proofApplied);
					// check the proof 
					MPTDictionaryPartial proof = MPTDictionaryPartial.deserialize(up.getProof());
					byte[] value = proof.get(adsId);
					boolean success = Arrays.equals(value, newAdsRoot);
					return Boolean.valueOf(success);
				}
			});
		}
		
		Scanner sc = new Scanner(System.in);
		logger.log(Level.INFO, "[Press enter to start client test]");
		sc.nextLine();
		sc.close();
		logger.log(Level.INFO, "starting time: "+LocalDateTime.now());
		long startTime = System.currentTimeMillis();
		try {
			logger.log(Level.INFO, "...making update requests");
			List<Future<Boolean>> updateResults = WORKERS.invokeAll(makeUpdateRequestWorkers, TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : updateResults) {
				Boolean resultBool = result.get();
				if(!resultBool) {
					logger.log(Level.WARNING, "UPDATE WAS NOT PERFORMED");
				}
			}
			logger.log(Level.INFO, "...update requests accepted, asking for proof of updates");
			List<Future<Boolean>> proofResults = WORKERS.invokeAll(verifyUpdatePerformedWorkers, TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
			logger.log(Level.INFO, "...making update requests");
			for (Future<Boolean> result : proofResults) {
				Boolean resultBool = result.get();
				if(!resultBool) {
					logger.log(Level.WARNING, "UPDATE WAS NOT PERFORMED");
				}
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		long endTime = System.currentTimeMillis();
		long duration = endTime-startTime;
		String timeTaken = String.format("TOTAL TIME: %d seconds %d milliseconds", 
			    TimeUnit.MILLISECONDS.toSeconds(duration),
			    duration - TimeUnit.MILLISECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(duration))
			);
		logger.log(Level.INFO, timeTaken);
		logger.log(Level.INFO, "[TEST COMPLETE!]");
	}
	
	
	public static void main(String[] args) {
		String base = System.getProperty("user.dir") + "/benchmark/throughput-simple-baseline/";
		int nClients = 1000;
		int nTotalADSes = 1000000;
		int nUpdates = 10000;
		// generateTestData(base, nClients, nTotalADSes, nUpdates);
		if (args.length != 3) {
			logger.log(Level.INFO, "please provide <host> <port> [SERVER|CLIENT]");
		}
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		if (args[2].equals("SERVER")) {
			runBenchmarkServer(base, host, port, nUpdates);
		}else if (args[2].equals("CLIENT")){
			runBenchmarkClients(base, host, port);
		}else {
			logger.log(Level.INFO, "please provide <host> <port> [SERVER|CLIENT]");

		}
	}	
}
