package bench;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
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

import pki.Account;
import pki.PKIDirectory;
import server.BVerifyServer;

public class ServerBasicThroughputWithUpdatesBenchmark {
	
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public static void generateTestData(String base) {
		BootstrapMockSetup.bootstrapSingleADSPerClient(10, base);
	}
	
	public static void runTest(String base, int batchSize, boolean checkUpdates) {
		String host = null;
		int port = 1099;
		// first create a registry
		try {
			LocateRegistry.createRegistry(port);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		
		// start up the server
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(base, host, port, batchSize);
		
		// now start up the mock clients
		PKIDirectory pki = new PKIDirectory(base+"pki/");
		Collection<Callable<Boolean>> workerThreads = new ArrayList<Callable<Boolean>>();
		for(Account a : pki.getAllAccounts()) {
			MockSimpleClient client = new MockSimpleClient(a, base, host, port);
			workerThreads.add(new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						client.sendRequest();
						Thread.sleep(1000);
						client.getAndCheckUpdates();
						System.out.println("COMPLETED");
						return Boolean.TRUE;
					}
				});
		}
		Scanner sc = new Scanner(System.in);
		System.out.println("Press enter to start test");
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
		System.out.println("DONE PROCESSING RESPONSES");
	}

	public static void main(String[] args) {
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/benchmarks/throughput-test-server-with-updates/";
		// generateTestData(base);
		runTest(base, 1, false);
	}
}
