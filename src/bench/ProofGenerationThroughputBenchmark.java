package bench;

import java.io.File;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.text.DecimalFormat;
import java.text.NumberFormat;
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
import java.util.stream.Collectors;

import client.Request;
import crpyto.CryptographicDigest;
import mpt.core.Utils;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import server.BVerifyServer;
import server.StartingData;

public class ProofGenerationThroughputBenchmark {
	private static final Logger logger = Logger.getLogger(UpdateThroughputBenchmark.class.getName());
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());
	private static final NumberFormat formatter = new DecimalFormat("#0.000");

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
			int port, int batchSize, int nBatches, Random prng){
		logger.log(Level.INFO, "...starting server on host: "+host+" port: "+port);
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
		// with no signature verification, since this just 
		// tests proof generation
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(host, port, data, batchSize, false);
		Request request = new Request(data);
		List<byte[]> adsIds = request.getADSIds();
		
		// do a bunch of updates
		for(int batch = 1; batch <= nBatches; batch++) {
			logger.log(Level.INFO, "commiting batch #"+batch+" of "+nBatches+" (batch size: "+batchSize+")");
			for(int update = 1; update <= batchSize; update++) {
				// select a random ADS to update
				int adsToUpdate = prng.nextInt(adsIds.size());
				byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
				byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
				// create the update request
				PerformUpdateRequest updateRequest = request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
						batch, false);
				byte[] response = server.getRequestHandler().performUpdate(updateRequest.toByteArray());
				
				// request should be accepted
				boolean accepted = Request.parsePerformUpdateResponse(response);
				if(!accepted) {
					throw new RuntimeException("something went wrong");
				}
			}
			try {
				// wait until commitment is added
				while(server.getRequestHandler().commitments().size() != batch+1) {
					Thread.sleep(10);
				}
			}catch (Exception e) {
				e.printStackTrace();
			}
		}
		logger.log(Level.INFO, "all batches committed, commmitments: ");
		try {
			List<byte[]> commitments = server.getRequestHandler().commitments();
			for(int i = 0; i < commitments.size(); i++) {
				logger.log(Level.INFO, "#"+i+" - "+Utils.byteArrayAsHexString(commitments.get(i)));
			}
		}catch(RemoteException e) {
			throw new RuntimeException(e.getMessage());
		}
		logger.log(Level.INFO, "...ready to benchmark proof generation throughput!");
		Scanner sc = new Scanner(System.in);
		logger.log(Level.INFO, "[Press enter to kill sever]");
		sc.nextLine();
		sc.close();
		server.shutdown();
	}
	
	public static void runBenchmarkClients(StartingData data, String host, 
			int port, Random prng) {
		logger.log(Level.INFO, "...creating mock clients connected to b_verify server \n "
				+ "on host: "+host+" port: "+port);
		// first connect to the registry 
		ClientProvider rmi = new ClientProvider(host, port);
		
		// next load the request module to help create requests
		logger.log(Level.INFO, "...loading initializing data");
		Request request = new Request(data);
		
		List<byte[]> adsIds = request.getADSIds();
		Collections.shuffle(adsIds, prng);
		
		logger.log(Level.INFO, "...creating proof requests");
		List<Callable<Boolean>> proofRequests  = adsIds.parallelStream().map(adsId -> {
			byte[] proveRequest = Request.createProveADSRootRequest(adsId).toByteArray();
			return new Callable<Boolean>() {
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
		}).collect(Collectors.toList());
		
		logger.log(Level.INFO, "..."+proofRequests.size()+" proof requests generated");		
		Scanner sc = new Scanner(System.in);
		try {
			/*
			 * Request proofs in parallel for EVERY ADS
			 */
			logger.log(Level.INFO, "[Press enter to make proof requests in parallel]");
			sc.nextLine();
			logger.log(Level.INFO, "...making proof requests");
			long startTime1 = System.currentTimeMillis();
			List<Future<Boolean>> results = WORKERS.invokeAll(proofRequests, 
					TOTAL_TASK_TIMEOUT, TimeUnit.SECONDS);
			for (Future<Boolean> result : results) {
				Boolean resultBool = result.get();
				if(!resultBool) {
					logger.log(Level.WARNING, "NO PROOF WAS RETURNED");
				}
			}
			long endTime1 = System.currentTimeMillis();
			long duration1 = endTime1 - startTime1;
			String timeTaken1 = formatter.format(duration1 / 1000d)+ " seconds";
			logger.log(Level.INFO, "Time taken to GENERATE "+adsIds.size()+" proofs "+timeTaken1);
			logger.log(Level.INFO, "...done!");
			sc.close();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
			sc.close();
		}

	}
	
	public static void main(String[] args) {
		// save the data so make sure tests are deterministic 
		File dataf = new File(System.getProperty("user.dir") + "/benchmarks/proof-throughput/test-data");
		int nClients = 1500;
		int maxClientsPerADS = 2;
		int nTotalADSes = 1000000;
		int nBatches = 10;
		int batchSize = 1000;
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
		if (args[2].equals("SERVER")) {
			runBenchmarkServer(data, host, port, batchSize, nBatches, new Random(9043901));
		}else if (args[2].equals("CLIENT")){
			runBenchmarkClients(data, host, port, new Random(35234));
		}else {
			logger.log(Level.INFO, "please provide <host> <port> [SERVER|CLIENT]");
		}
	}	
	
}
