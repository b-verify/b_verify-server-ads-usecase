package bench;

import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
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

import org.apache.commons.io.FileUtils;

import pki.Account;
import pki.PKIDirectory;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import server.BVerifyServer;
import server.BVerifyServerUpdateVerifier;

public class ServerSimpleThroughputBenchmark {
	private static final Logger logger = Logger.getLogger(ServerSimpleThroughputBenchmark.class.getName());

	
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
		
	/*
	 * Run this once to generate the data for the benchmark
	 */
	public static void generateTestData(String base, int numberOfClients) {
		logger.log(Level.INFO, "...resetting the test data");
		BootstrapMockSetup.resetDataDir(base);
		logger.log(Level.INFO, "...generating test data for simple throughput benchmark");
		BootstrapMockSetup.bootstrapSingleADSPerClient(base, numberOfClients);
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
			byte[] requestAsBytes = request.toByteArray();
			workerThreads.add(new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						rmi.getServer().performUpdate(requestAsBytes);
						return Boolean.TRUE;
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
				System.out.println(resultBool);
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		logger.log(Level.INFO, "TEST COMPLETE!");
	}

	public static void main(String[] args) {
		String base = System.getProperty("user.dir") + "/benchmark/throughput-simple/";
		int nClients = 10;
		generateTestData(base, nClients);
		runBenchmark(base, nClients);
	}
}
