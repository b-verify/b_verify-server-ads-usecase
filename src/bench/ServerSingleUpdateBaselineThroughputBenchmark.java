package bench;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.protobuf.ByteString;

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
	
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 120;
		
	/*
	 * Run this once to generate the data for the benchmark
	 */
	public static void generateTestData(String base, int nClients, int nTotalADSes, int nUpdates) {
		logger.log(Level.INFO, "...resetting the test data");
		BootstrapMockSetup.resetDataDir(base);
		logger.log(Level.INFO, "...generating test data for simple throughput benchmark");
		BootstrapMockSetup.bootstrapSingleADSUpdates(base, nClients, nTotalADSes, nUpdates);	
	}
	
	/*
	 * Actually run the benchmark
	 */
	public static void runBenchmark(String base, int batchSize) {
		String host = null;
		int port = 1099;
		
		// first create a registry
		try {
			LocateRegistry.createRegistry(port);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		
		ClientProvider rmi = new ClientProvider(host, port);
		
		// start up the server
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(base, host, port, batchSize);
		
		// now through requests at its
		List<PerformUpdateRequest> requests = BootstrapMockSetup.loadPerformUpdateRequests(base);
		
		Collection<Callable<Boolean>> workerThreads = new ArrayList<Callable<Boolean>>();
		
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
			
			
			workerThreads.add(new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						// request the update
						rmi.getServer().performUpdate(updateRequestAsBytes);
						Thread.sleep(30*1000);
						
						// ask for a proof it was applied 
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
		logger.log(Level.INFO, "Press enter to start test");
		sc.nextLine();
		sc.close();
		try {
			List<Future<Boolean>> results = WORKERS.invokeAll(workerThreads, TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : results) {
				Boolean resultBool = result.get();
				logger.log(Level.INFO, "performed update: "+resultBool);
				if(!resultBool) {
					throw new RuntimeException("server did not update - test failed");
				}
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		logger.log(Level.INFO, "TEST COMPLETE!");
	}

	public static void main(String[] args) {
		String base = System.getProperty("user.dir") + "/benchmark/throughput-simple-baseline/";
		int nClients = 1000;
		int nTotalADSes = 1000000;
		int nUpdates = 10000;
		generateTestData(base, nClients, nTotalADSes, nUpdates);
		runBenchmark(base, nUpdates);
	}
}
