package bench;

import java.io.File;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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

import client.Request;
import crpyto.CryptographicDigest;
import rmi.ClientProvider;
import server.BVerifyServer;
import server.StartingData;

public class ThroughputBenchmark {
	private static final Logger logger = Logger.getLogger(ThroughputBenchmark.class.getName());
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());
	private static final NumberFormat formatter = new DecimalFormat("#0.000");

	/*
	 * Adjust the number of threads, timeouts and delays 
	 * based on how the test is being run and the number 
	 * of cores & memory on the testing machine
	 */
	private static final int NUMBER_OF_THREADS = 100;
	private static final int TOTAL_TASK_TIMEOUT = 120;
	private static final int MILLISECONDS_OF_RANDOM_DELAY = 100;
	private static final ThreadPoolExecutor WORKERS = 
			new ThreadPoolExecutor(NUMBER_OF_THREADS, // keep these threads alive even if idle
								   NUMBER_OF_THREADS, // total size of thread pool
								   30, // idle timeout
								    TimeUnit.SECONDS,
								    // can also queue up to 10k tasks
								    new ArrayBlockingQueue<Runnable>(10000));
	
		
	/*
	 * Run this once to generate the data for the benchmark
	 */
	public static void generateTestData(int nClients, int maxClientsPerADS, int nTotalADSes, File f) {
		StartingData data = new StartingData(nClients, maxClientsPerADS, nTotalADSes, START_VALUE );
		data.saveToFile(f);
	}
	
	public static void runBenchmarkServer(StartingData data, String host, 
			int port, int batchSize, boolean requireSignatures) {
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
		
		// start up the server (also on local-host)
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(host, port, data, batchSize, requireSignatures);
		logger.log(Level.INFO, "...ready!");
		Scanner sc = new Scanner(System.in);
		logger.log(Level.INFO, "[Press enter to kill sever]");
		sc.nextLine();
		sc.close();
		server.shutdown();
	}
	
	public static void runBenchmarkClients(StartingData data, String host, 
			int port, int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, "...creating mock clients connected to b_verify server \n "
				+ "on host: "+host+" port: "+port);
		// first connect to the registry 
		ClientProvider rmi = new ClientProvider(host, port);
		
		// next load the request module tohelp create requests
		Request request = new Request(data);
		
		// now prepare requests to throw at it
		Collection<Callable<Boolean>> makeUpdateRequestWorkers = new ArrayList<Callable<Boolean>>();
		Collection<Callable<Boolean>> verifyUpdatePerformedWorkers = new ArrayList<Callable<Boolean>>();
		
		List<byte[]> adsIds = request.getADSIds();
		Collections.shuffle(adsIds);
		for(int update = 0; update < batchSize; update++) {
			byte[] adsId = adsIds.get(update);
			byte[] newValue = CryptographicDigest.hash(("new value"+update).getBytes());
			byte[] performRequest = 
					request.createPerformUpdateRequest(adsId, newValue, 1, requireSignatures)
					.toByteArray();
			byte[] proveRequest = Request.createProveADSRootRequest(adsId)
					.toByteArray();

			
			makeUpdateRequestWorkers.add(new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						// request the update
						Random rand = new Random();
						Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
						byte[] responseBytes = rmi.getServer().performUpdate(performRequest);
						return Boolean.valueOf(Request.parsePerformUpdateResponse(responseBytes));
					}
			});
			verifyUpdatePerformedWorkers.add(new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					// ask for a proof it was applied 
					Random rand = new Random();
					Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
					rmi.getServer().proveADSRoot(proveRequest);
					return Boolean.valueOf(true);
				}
			});
		}
		
		Scanner sc = new Scanner(System.in);
		try {
			
			/*
			 * Test #1 - make requests 
			 */
			logger.log(Level.INFO, "[Press enter to make requests]");
			sc.nextLine();
			logger.log(Level.INFO, "... making update requests");
			long startTime1 = System.currentTimeMillis();
			List<Future<Boolean>> updateResults = WORKERS.invokeAll(makeUpdateRequestWorkers, TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : updateResults) {
				Boolean resultBool = result.get();
				if(!resultBool) {
					logger.log(Level.WARNING, "UPDATE WAS NOT PERFORMED");
				}
			}
			long endTime1 = System.currentTimeMillis();
			long duration1 = endTime1 - startTime1;
			String timeTaken1 = formatter.format(duration1 / 1000d)+ " seconds";
			
			/*
			 * Test #2 - ask for proofs that a request has been performed
			 */
			logger.log(Level.INFO, "[Press enter to ask for proofs]");
			sc.nextLine();
			logger.log(Level.INFO, "... making proof requests");
			long startTime2 = System.currentTimeMillis();
			List<Future<Boolean>> proofResults = WORKERS.invokeAll(verifyUpdatePerformedWorkers, TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
			logger.log(Level.INFO, "...making update requests");
			for (Future<Boolean> result : proofResults) {
				Boolean resultBool = result.get();
				if(!resultBool) {
					logger.log(Level.WARNING, "UPDATE WAS NOT PERFORMED");
				}
			}
			long endTime2 = System.currentTimeMillis();
			long duration2 = endTime2 - startTime2;
			String timeTaken2 = formatter.format(duration2 / 1000d)+ " seconds";
			
			logger.log(Level.INFO, "Time taken to request updates: "+timeTaken1);
			logger.log(Level.INFO, "Time taken to verify updates: "+timeTaken2);
			logger.log(Level.INFO, "[TEST COMPLETE!]");
			sc.close();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
			sc.close();
		}

	}
	
	
	public static void main(String[] args) {
		File dataf = new File(System.getProperty("user.dir") + "/benchmarks/throughput-baseline/init");
		int nClients = 1500;
		int maxClientsPerADS = 2;
		int nTotalADSes = 1000000;
		int nUpdates = 10000;
		if (args.length != 3) {
			generateTestData(nClients, maxClientsPerADS, nTotalADSes, dataf);
			logger.log(Level.INFO, "test data generated"+"\n"+
					"to run test provide <host> <port> [SERVER|CLIENT]");
			return;
		}
		StartingData data = StartingData.loadFromFile(dataf);
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		if (args[2].equals("SERVER")) {
			runBenchmarkServer(data, host, port, nUpdates, true);
		}else if (args[2].equals("CLIENT")){
			runBenchmarkClients(data, host, port, nUpdates, true);
		}else {
			logger.log(Level.INFO, "please provide <host> <port> [SERVER|CLIENT]");
		}
	}	
}
