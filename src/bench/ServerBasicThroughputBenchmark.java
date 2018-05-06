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

import api.BVerifyProtocolServerAPI;
import rmi.ClientProvider;
import server.BVerifyServer;

public class ServerBasicThroughputBenchmark {
	
	private static final ExecutorService WORKERS = Executors.newCachedThreadPool();
	private static final int TIMEOUT = 60;
	
	public static void generateTestData(String base) {
		BootstrapMockSetup.bootstrapSingleADSPerClientGenerateUpdates(1000, 10, base);
	}
	
	public static void runTest(String base, int batchSize, boolean checkUpdates) {
		// load the requests
		List<byte[]> requests = BootstrapMockSetup.loadTransactionRequests(base);
		
		String host = null;
		int port = 1099;
		// first create a registry
		try {
			LocateRegistry.createRegistry(port);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		@SuppressWarnings("unused")
		BVerifyServer server = new BVerifyServer(base, host, port, batchSize);
		ClientProvider rmi = new ClientProvider(host, port);
		Scanner sc = new Scanner(System.in);
		System.out.println("Press enter to start test");
		sc.nextLine();
		sc.close();
		Collection<Callable<Boolean>> approvals = new ArrayList<Callable<Boolean>>();
		for(byte[] request : requests) {
			approvals.add(new Callable<Boolean>() {
				@Override
				public Boolean call() throws Exception {
					BVerifyProtocolServerAPI stub = rmi.getServer();
					System.out.println("Making update request: "+request);
					boolean response = stub.performUpdate(request);
					System.out.println(response);
					return Boolean.valueOf(response);
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
		// now check that the requests have been performed
		if(checkUpdates) {
			try {
				// wait one second
				Thread.sleep(1000);
				BVerifyProtocolServerAPI stub = rmi.getServer();
				for(byte[] request : requests) {
					RequestADSUpdates requestMsg = RequestADSUpdates.parseFrom(request);
					for(ADSModificationRequest modification : requestMsg.getModificationsList()) {
						byte[] adsRoot = stub.getAuthenticationObjectNoProof(modification.getAdsId().toByteArray());
						boolean updated = Arrays.equals(adsRoot, modification.getNewValue().toByteArray());
						System.out.println("checking update: "+updated);
					}
				}
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void main(String[] args) {
		String base = "/home/henryaspegren/eclipse-workspace/b_verify-server/benchmarks/throughput-test-server-basic/";
		// generateTestData(base);
		runTest(base, 100, false);
	}
	
}
