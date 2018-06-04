package bench;

import java.io.File;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
import java.util.stream.IntStream;

import client.Request;
import crpyto.CryptographicDigest;
import rmi.ClientProvider;
import server.BVerifyServer;
import server.StartingData;

public class UpdateThroughputBenchmark {
	private static final Logger logger = Logger.getLogger(UpdateThroughputBenchmark.class.getName());
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());
	private static final NumberFormat formatter = new DecimalFormat("#0.000");

	/*
	 * SIMULATION:
	 * 
	 * Adjust the number of threads, timeouts and delays
	 * to simulate different client loads. 
	 * 
	 * Note that these parameters are constrained 
	 * based on how the test is being run and the number 
	 * of cores & memory on the testing machine
	 */
	private static final int NUMBER_OF_THREADS = 500;
	private static final int TOTAL_TASK_TIMEOUT = 120;
	private static final int MILLISECONDS_OF_RANDOM_DELAY = 50;
	private static final ThreadPoolExecutor WORKERS = 
			new ThreadPoolExecutor(NUMBER_OF_THREADS, // keep these threads alive even if idle
								   NUMBER_OF_THREADS, // total size of thread pool
								   30, // idle timeout
								    TimeUnit.SECONDS,
								    // can also queue up to 100k tasks
								    new ArrayBlockingQueue<Runnable>(100000));
	
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
		// first create a registry on local host
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
			int port, int nSingleADSUpdates, int nDoubleADSUpdates, 
			Random prng, boolean requireSignatures) {
		
		logger.log(Level.INFO, "...creating mock clients connected to b_verify server \n "
				+ "on host: "+host+" port: "+port);
		// first connect to the registry 
		ClientProvider rmi = new ClientProvider(host, port);
		
		// next load the request module to help create requests
		logger.log(Level.INFO, "...loading initializing data");
		Request request = new Request(data);
		
		// now prepare requests to throw at it
		int totalNumberOfUpdates = nSingleADSUpdates + nDoubleADSUpdates;
		@SuppressWarnings("unchecked")
		Callable<Boolean>[] updateRequests = new Callable[totalNumberOfUpdates];
		@SuppressWarnings("unchecked")
		Callable<Boolean>[] verifyRequests = new Callable[totalNumberOfUpdates];
		
		List<byte[]> adsIds = request.getADSIds();
		Collections.shuffle(adsIds, prng);
		
		logger.log(Level.INFO, "...creating mock updates");
		
		IntStream.range(0, totalNumberOfUpdates).parallel().forEach( updateNumber -> {
			byte[] performRequest;
			byte[] proveRequest;
			// single ads update ( = receipt issuance / redemption )
			if(updateNumber < nSingleADSUpdates) {
				byte[] adsId = adsIds.get(updateNumber);
				byte[] newValue = CryptographicDigest.hash(("new value"+updateNumber).getBytes());
				performRequest = request.createPerformUpdateRequest(adsId, newValue, 1, requireSignatures)
						.toByteArray();
				proveRequest = Request.createProveADSRootRequest(adsId)
						.toByteArray();
			} else {
				// double ads update ( = receipt transfer )
				int i = updateNumber-nSingleADSUpdates;
				int x = nSingleADSUpdates+2*i;
				int y = nSingleADSUpdates+2*i+1;
				byte[] adsIdX = adsIds.get(x);
				byte[] adsIdY = adsIds.get(y);
				byte[] newValueX = CryptographicDigest.hash(("new value"+x).getBytes());
				byte[] newValueY = CryptographicDigest.hash(("new value"+y).getBytes());
				List<Map.Entry<byte[], byte[]>> adsModifications = Arrays.asList(
						Map.entry(adsIdX, newValueX),
						Map.entry(adsIdY, newValueY));
				performRequest = request.createPerformUpdateRequest(adsModifications, 1, requireSignatures)
						.toByteArray();
				// the proof should be the same for either....
				proveRequest = Request.createProveADSRootRequest(adsIdX)
						.toByteArray();
			}
			
			updateRequests[updateNumber] = new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					// request the update
					Random rand = new Random();
					Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
					byte[] responseBytes = rmi.getServer().performUpdate(performRequest);
					return Boolean.valueOf(Request.parsePerformUpdateResponse(responseBytes));
				}
			};
			verifyRequests[updateNumber] = new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					// ask for a proof it was applied 
					Random rand = new Random();
					Thread.sleep(rand.nextInt(MILLISECONDS_OF_RANDOM_DELAY));
					// for benchmarking we don't include the time required to 
					// actually check the validity of the proof
					rmi.getServer().proveADSRoot(proveRequest);
					return Boolean.valueOf(true);
				}
			};
		});
		
		logger.log(Level.INFO, "...request generated");

		Collection<Callable<Boolean>> requestUpdates = Arrays.asList(updateRequests);
		Collection<Callable<Boolean>> requestProofs = Arrays.asList(verifyRequests);
		
		Scanner sc = new Scanner(System.in);
		try {
			
			/*
			 * Test #1 - make requests 
			 */
			logger.log(Level.INFO, "[Press enter to make requests]");
			sc.nextLine();
			logger.log(Level.INFO, "... making update requests");
			long startTime1 = System.currentTimeMillis();
			List<Future<Boolean>> updateResults = WORKERS.invokeAll(requestUpdates, 
					TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
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
			List<Future<Boolean>> proofResults = WORKERS.invokeAll(requestProofs, 
					TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
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
			
			logger.log(Level.INFO, "Time taken to REQUEST [single ADS Updates "+nSingleADSUpdates+"| double ADS Updates "+
					nDoubleADSUpdates+"]: "+timeTaken1);
			logger.log(Level.INFO, "Time taken to VERIFY [single ADS Updates "+nSingleADSUpdates+"| double ADS Updates "+
					nDoubleADSUpdates+"]: "+timeTaken2);
			logger.log(Level.INFO, "[TEST COMPLETE!]");
			sc.close();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
			sc.close();
		}

	}
	
	public static void main(String[] args) {
		// save the data so make sure tests are deterministic 
		File dataf = new File(System.getProperty("user.dir") + "/benchmarks/update-throughput/test-data");
		int nClients = 1500;
		int maxClientsPerADS = 2;
		int nTotalADSes = 1000000;
		// in example application = receipt issuance/redemption
		int nSingleADSUpdates = 100000;
		// in example application = receipt transfer
		int nDoubleADSUpdates = 0;
		if (args.length != 3) {
			generateTestData(nClients, maxClientsPerADS, nTotalADSes, dataf);
			logger.log(Level.INFO, "test data generated"+"\n"+
					"to run test provide <host> <port> [SERVER|CLIENT]");
			return;
		}
		StartingData data = StartingData.loadFromFile(dataf);
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		// for deterministic tests
		Random prng = new Random(9043901);
		if (args[2].equals("SERVER")) {
			int batchSize = nSingleADSUpdates+nDoubleADSUpdates;
			runBenchmarkServer(data, host, port, batchSize, true);
		}else if (args[2].equals("CLIENT")){
			runBenchmarkClients(data, host, port, nSingleADSUpdates, nDoubleADSUpdates, prng, true);
		}else {
			logger.log(Level.INFO, "please provide <host> <port> [SERVER|CLIENT]");
		}
	}	
}
