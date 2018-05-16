package bench;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import client.Request;
import crpyto.CryptographicDigest;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import serialization.generated.MptSerialization.MerklePrefixTrie;
import server.BVerifyServer;
import server.StartingData;

public class ProofSizeBenchmark {
	private static final Logger logger = Logger.getLogger(ProofSizeBenchmark.class.getName());
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());
	
	private final BVerifyServer server;
	private final Request request;
	
	private final int nADSes;
	private final int batchSize;
	
	public ProofSizeBenchmark(int nClients, int nClientsPerAdsMax, int nADSes, int batchSize) {
		StartingData data = new StartingData(nClients, nClientsPerAdsMax, nADSes, START_VALUE);
		this.nADSes = nADSes;
		this.batchSize = batchSize;
		
		// turn signature checking off
		this.server = new BVerifyServer(data, batchSize, false);
		this.request = new Request(data);
	}
	
	public void runProofSizeSingleADS(int nUpdates, String fileName) {
		List<List<String>> rows = new ArrayList<>();
		
		// set a deterministic prng for repeatable tests
		Random rand = new Random(91012);
		
		List<byte[]> adsIds = this.request.getADSIds();

		byte[] adsIdToNotUpdate = adsIds.get(0);
		
		// initial proof size
		ProofSize size = this.getProofSize(adsIdToNotUpdate);
		rows.add(getCSVRowSingleADSProofSize(nADSes, 0, batchSize, size.getRawProofSize(), 
				size.getUpdateSize(), size.getUpdateProofSize(), size.getFreshnessProofSize()));
		
		int validAt = 1;
		
		for(int update = 1; update <= nUpdates; update++) {
			// select a random ADS to update
			int adsToUpdate = rand.nextInt(adsIds.size()-1)+1;
			byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
			byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
			
			// create the update request
			PerformUpdateRequest request = this.request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
					validAt, false);
			byte[] response = this.server.getRequestHandler().performUpdate(request.toByteArray());
			
			// request should be accepted
			boolean accepted = Request.parsePerformUpdateResponse(response);
			if(!accepted) {
				throw new RuntimeException("something went wrong");
			}
			
			if((update % batchSize) == 0) {
				size = this.getProofSize(adsIdToNotUpdate);
				rows.add(getCSVRowSingleADSProofSize(nADSes, update, batchSize, size.getRawProofSize(), 
						size.getUpdateSize(), size.getUpdateProofSize(), size.getFreshnessProofSize()));
				validAt++;
			}
		}
		writeSingleADSProofSizeToCSV(rows, fileName);
		
		this.server.shutdown();;
	}
	
	public static List<String> getCSVRowSingleADSProofSize(int nADSes, int nUpdates, int batchSize, 
			int proofSize, int updateSize, int updateProofSize, int freshnessProofSize) {
		return Arrays.asList(String.valueOf(nADSes), String.valueOf(nUpdates), 
				String.valueOf(batchSize), String.valueOf(proofSize),
				String.valueOf(updateSize), String.valueOf(updateProofSize),
				String.valueOf(freshnessProofSize));
	}
	
	public static void writeSingleADSProofSizeToCSV(List<List<String>> results, String csvFile) {
		try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(csvFile));
				CSVPrinter csvPrinter = new CSVPrinter(writer, 
						CSVFormat.DEFAULT.withHeader("nADSes", "nUpdates", "batchSize", 
								"proofSizeTotal", "updateSize", "updateProofSize", "freshnessProofSize"));) {
			for(List<String> resultRow : results) {
				csvPrinter.printRecord(resultRow);
			}
			csvPrinter.flush();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public ProofSize getProofSize(byte[] adsId) {
		logger.log(Level.FINE, "getting proof size for ADS ID: "+Utils.byteArrayAsHexString(adsId));
		ProveADSRootRequest request = Request.createProveADSRootRequest(adsId);
		try {
			// request a proof
			// and record the length
			byte[] proof = this.server.getRequestHandler().proveADSRoot(request.toByteArray());
			
			int rawProofSize = proof.length;
			ProveADSRootResponse proofResponse = Request.parseProveADSResponse(proof);
			int sizeUpdate = proofResponse.getProof().getLastUpdate().getSerializedSize();
			int sizeUpdateProof = proofResponse.getProof().getLastUpdatedProof().getSerializedSize();
			int sizeFreshnessProof = 0;
			for(MerklePrefixTrie mpt : proofResponse.getProof().getFreshnessProofList()) {
				sizeFreshnessProof+= mpt.getSerializedSize();
			}
			return new ProofSize(rawProofSize, sizeUpdate, sizeUpdateProof, sizeFreshnessProof);
			
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static void main(String[] args) {
		
		// small test: 100000 ADS, each batch is 1% (1k) of ADSes
		//						   and 10 batches total (~10% of ADSes updated)
		ProofSizeBenchmark benchSmall = new ProofSizeBenchmark(500, 2, 100000, 1000);
		String smallTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"small_proof_size_test.csv";
		benchSmall.runProofSizeSingleADS(10000, smallTest);
	
		
		// medium test: 1M ADS - each batch is 1% (10k) of ADSes
		//				         and 10 batches total (~10% of ADSes updated)
		ProofSizeBenchmark benchMedium = new ProofSizeBenchmark(1500, 2, 1000000, 10000);
		String mediumTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"medium_proof_size_test.csv";
		benchMedium.runProofSizeSingleADS(100000, mediumTest);
		
		// large test: 10M ADS - each update is 1% (100k) of ADSes
		//						 and 10 batches total (~10 % of ADSes updated
		ProofSizeBenchmark benchLarge = new ProofSizeBenchmark(5000, 2, 10000000, 100000);
		String largeTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"large_proof_size_test.csv";
		benchLarge.runProofSizeSingleADS(1000000, largeTest);
		
	}
}
