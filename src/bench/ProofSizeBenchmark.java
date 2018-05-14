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

import bench.MockTester.ProofSize;
import crpyto.CryptographicDigest;

public class ProofSizeBenchmark {
	
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());

	public static void runProofSizeSingleADS(int nClients, int nClientsPerAdsMax, int nUpdates, int batchSize) {
		List<List<String>> rows = new ArrayList<>();
		// set a deterministic prng for repeatable tests
		Random rand = new Random(91012);
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, batchSize, START_VALUE);
		List<byte[]> adsIds = tester.getADSIds();
		int nADSes = adsIds.size();
		byte[] adsIdToNotUpdate = adsIds.get(0);
		for(int update = 1; update <= nUpdates; update++) {
			int adsToUpdate = rand.nextInt(adsIds.size()-1)+1;
			byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
			byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
			boolean accepted = tester.doUpdate(adsIdToUpdate, newValue);
			if(!accepted) {
				throw new RuntimeException("something went wrong");
			}
			ProofSize size = tester.getProofSize(adsIdToNotUpdate);
			rows.add(getCSVRowSingleADSProofSize(nADSes, update, batchSize, size.getRawProofSize(), 
					size.getUpdateSize(), size.getUpdateProofSize(), size.getFreshnessProofSize()));
		}
		writeSingleADSProofSizeToCSV(rows, "./proofsizebenchmark.csv");
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
		runProofSizeSingleADS(1000, 2, 250000, 10000);
	}
}
