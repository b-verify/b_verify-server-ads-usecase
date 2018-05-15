package bench;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import bench.ProofSize;
import crpyto.CryptographicDigest;

public class ProofSizeBenchmark {
	
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());

	public static void runProofSizeSingleADS(int nClients, int nClientsPerAdsMax, int nADSes, int nUpdates, int batchSize,
			String fileName) {
		List<List<String>> rows = new ArrayList<>();
		// set a deterministic prng for repeatable tests
		Random rand = new Random(91012);
		
		// we disable signatures checking 
		// for the benchmarks - speeds things up dramatically 
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADSes, batchSize, START_VALUE, false);
		List<byte[]> adsIds = tester.getADSIds();
		assert adsIds.size() == nADSes;
		byte[] adsIdToNotUpdate = adsIds.get(0);
		
		// initial proof size
		ProofSize size = tester.getProofSize(adsIdToNotUpdate);
		rows.add(getCSVRowSingleADSProofSize(nADSes, 0, batchSize, size.getRawProofSize(), 
				size.getUpdateSize(), size.getUpdateProofSize(), size.getFreshnessProofSize()));
				
		for(int update = 1; update <= nUpdates; update++) {
			int adsToUpdate = rand.nextInt(adsIds.size()-1)+1;
			byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
			byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
			boolean accepted = tester.doUpdate(adsIdToUpdate, newValue);
			if(!accepted) {
				throw new RuntimeException("something went wrong");
			}
			if((update % batchSize) == 0) {
				size = tester.getProofSize(adsIdToNotUpdate);
				rows.add(getCSVRowSingleADSProofSize(nADSes, update, batchSize, size.getRawProofSize(), 
						size.getUpdateSize(), size.getUpdateProofSize(), size.getFreshnessProofSize()));
			}
		}
		writeSingleADSProofSizeToCSV(rows, fileName);
		tester.shutdown();
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
	
	public static void main(String[] args) {
		
		// small test: 100000 ADS, update is 1% (1k) of ADSes
		//						   and 10 updates total (total ~10% of ADSes updated)
		String smallTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"small_proof_size_test.csv";
		runProofSizeSingleADS(500, 2, 100000, 10000, 1000, smallTest);
	
		
		// medium test: 1M ADS - each update is 1% (10k) of ADSes
		//				         and 10 updates (total ~ 10% of ADSes updated)
		String mediumTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"medium_proof_size_test.csv";
		runProofSizeSingleADS(1500, 2, 1000000, 100000, 10000, mediumTest);
	}
}
