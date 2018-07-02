package bench;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import client.Request;
import crpyto.CryptographicDigest;
import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryPartial;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import serialization.generated.MptSerialization.MerklePrefixTrie;
import server.BVerifyServer;
import server.StartingData;

/**
 * This code was used to the proof size benchmarks 
 * used in the b\_verify paper. The exact test data to reproduce these 
 * proofs is available on request, but is too large to include 
 * in the repo. Similar results can be obtained by generating random 
 * test data for the similar size. 
 * 
 * @author henryaspegren
 *
 */

/*
 * NOTE on deterministic tests - Java cryptographic libraries make it 
 * difficult to generate key pairs deterministically (which would normally
 * be something that users should never do). As a result if we are not careful
 * we will get slight differences from run to run. 
 */

public class ProofSizeBenchmark {
	private static final Logger logger = Logger.getLogger(ProofSizeBenchmark.class.getName());
	
	private final BVerifyServer server;
	private final Request request;
	
	private final int nADSes;
	private final int batchSize;
	
	// one ads modified 
	private final byte[] adsIdLastUpdatedWithSingleAdsMod;
	
	// two ads modified
	private final byte[] adsIdLastUpdatedWithDoubleAdsModA;
	private final byte[] adsIdLastUpdatedWithDoubleAdsModB;
	
	// three ADS modified 
	private final byte[] adsIdLastUpdatedWithThreeAdsModA;
	private final byte[] adsIdLastUpdatedWithThreeAdsModB;
	private final byte[] adsIdLastUpdatedWIthThreeAdsModC;
	
	
	private final List<byte[]> adsIdsToUpdate;
	
	public ProofSizeBenchmark(StartingData data, int batchSize) {
		// turn signature checking off - speeds up test but does not affect 
		// proof sizes
		this.server = new BVerifyServer(data, batchSize, false);
		this.request = new Request(data);
		this.nADSes = this.request.getADSIds().size();
		this.batchSize = batchSize;
		
		List<byte[]> adsIds = this.request.getADSIds();
		Collections.shuffle(adsIds, new Random(1034243));
		
		// the first ADS ID we update individually
		this.adsIdLastUpdatedWithSingleAdsMod = adsIds.get(0);
		// the second ADS ID we update as part of an update to two ADS IDs
		this.adsIdLastUpdatedWithDoubleAdsModA = adsIds.get(1);
		this.adsIdLastUpdatedWithDoubleAdsModB = adsIds.get(2);
		// the third ADS ID we update as part of an update to three ADS IDs
		this.adsIdLastUpdatedWithThreeAdsModA = adsIds.get(3);
		this.adsIdLastUpdatedWithThreeAdsModB = adsIds.get(4);
		this.adsIdLastUpdatedWIthThreeAdsModC = adsIds.get(5);
		
		this.adsIdsToUpdate = adsIds.subList(6, adsIds.size());
		
		int batch = 1;
		boolean requireSignatures = true;
		Random prng = new Random(17021);
		
		for(int update = 1; update <= this.batchSize; update++) {
			PerformUpdateRequest request;
			if(update == 1) {
				byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
				request = this.request.createPerformUpdateRequest(this.adsIdLastUpdatedWithSingleAdsMod, newValue, 
						batch, requireSignatures);
			}else if (update == 2) {
				byte[] newValueA =  CryptographicDigest.hash(("NEW VALUE A").getBytes());
				byte[] newValueB =  CryptographicDigest.hash(("NEW VALUE B").getBytes());
				List<Map.Entry<byte[], byte[]>> updates = Arrays.asList(Map.entry(this.adsIdLastUpdatedWithDoubleAdsModA, newValueA), 
						Map.entry(this.adsIdLastUpdatedWithDoubleAdsModB, newValueB));
				 request = this.request.createPerformUpdateRequest(updates,batch, requireSignatures);
			}else if (update == 3) {
				byte[] newValueA =  CryptographicDigest.hash(("NEW VALUE A").getBytes());
				byte[] newValueB =  CryptographicDigest.hash(("NEW VALUE B").getBytes());
				byte[] newValueC =  CryptographicDigest.hash(("NEW VALUE B").getBytes());
				List<Map.Entry<byte[], byte[]>> updates = Arrays.asList(Map.entry(this.adsIdLastUpdatedWithThreeAdsModA, newValueA), 
						Map.entry(this.adsIdLastUpdatedWithThreeAdsModB, newValueB),
						Map.entry(this.adsIdLastUpdatedWIthThreeAdsModC, newValueC));
				request = this.request.createPerformUpdateRequest(updates, batch, requireSignatures);
			}else {
				int adsToUpdate = prng.nextInt(this.adsIdsToUpdate.size());	
				byte[] adsIdToUpdate = this.adsIdsToUpdate.get(adsToUpdate);
				byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
				request = this.request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
					batch, requireSignatures);
			}
			byte[] response = this.server.getRequestHandler().performUpdate(request.toByteArray());
			
			// request should be accepted
			boolean accepted = Request.parsePerformUpdateResponse(response);
			if(!accepted) {
				throw new RuntimeException("something went wrong");
			}
		}
		try {
			// wait until commitment is added
			while(this.server.getRequestHandler().commitments().size() != batch+1) {
				Thread.sleep(10);
			}
		}catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public void runProofSizeBenchmark(int nUpdateBatches, String fileName) {
		List<List<String>> rows = new ArrayList<>();
		
		// set a deterministic prng for repeatable tests
		Random prng = new Random(91012);
			
		// initial proof sizes
		ProofSize sizeSingle = this.getProofSize(this.adsIdLastUpdatedWithSingleAdsMod);
		ProofSize sizeDouble =  this.getProofSize(this.adsIdLastUpdatedWithDoubleAdsModA);
		ProofSize sizeTriple = this.getProofSize(this.adsIdLastUpdatedWithThreeAdsModA);
		
		rows.add(getCSVRowProofSize(nADSes, 0, sizeSingle));
		rows.add(getCSVRowProofSize(nADSes, 0, sizeDouble));
		rows.add(getCSVRowProofSize(nADSes, 0, sizeTriple));

		for(int batch = 2; batch <= nUpdateBatches+1; batch++) {
			for(int update = 1; update <= batchSize; update++) {
				// select a random ADS to update
				int adsToUpdate = prng.nextInt(this.adsIdsToUpdate.size());
				byte[] adsIdToUpdate = this.adsIdsToUpdate.get(adsToUpdate);
				byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
				
				// create the update request
				PerformUpdateRequest request = this.request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
						batch, false);
				byte[] response = this.server.getRequestHandler().performUpdate(request.toByteArray());
				
				// request should be accepted
				boolean accepted = Request.parsePerformUpdateResponse(response);
				if(!accepted) {
					throw new RuntimeException("something went wrong");
				}
			}
			try {
				// wait until commitment is added
				while(this.server.getRequestHandler().commitments().size() != batch+1) {
					Thread.sleep(10);
				}
			}catch (Exception e) {
				e.printStackTrace();
			}
			
			// updates proof sizes
			sizeSingle = this.getProofSize(this.adsIdLastUpdatedWithSingleAdsMod);
			sizeDouble =  this.getProofSize(this.adsIdLastUpdatedWithDoubleAdsModA);
			sizeTriple = this.getProofSize(this.adsIdLastUpdatedWithThreeAdsModA);
			
			int nUpdates = (batch-1)*batchSize;
			rows.add(getCSVRowProofSize(nADSes, nUpdates, sizeSingle));
			rows.add(getCSVRowProofSize(nADSes, nUpdates, sizeDouble));
			rows.add(getCSVRowProofSize(nADSes, 0, sizeTriple));

		}
		writeProofSizeRowsToCSV(rows, fileName);
		this.server.shutdown();
	}
	
	public static List<String> getCSVRowProofSize(int nADSes, int nUpdates, ProofSize size) {
		return Arrays.asList(String.valueOf(nADSes), String.valueOf(nUpdates),
				String.valueOf(size.getRawProofSize()), String.valueOf(size.getUpdateSize()), 
				String.valueOf(size.getNSignatures()), 
				String.valueOf(size.getSignaturesSize()),
				String.valueOf(size.getUpdateProofSize()),
				String.valueOf(size.getFreshnessProofSize()), String.valueOf(size.getFreshnessProofNoOptimizationSize()));
	}
	
	public static void writeProofSizeRowsToCSV(List<List<String>> results, String csvFile) {
		try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(csvFile));
				CSVPrinter csvPrinter = new CSVPrinter(writer, 
						CSVFormat.DEFAULT.withHeader("nADSes", "nUpdates",
								"proofSizeTotal", "updateSize", "nSignatures", "signaturesSize",
								"updateProofSize", "freshnessProofSize", "freshnessProofNoOptimizationSize"));) {
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
		logger.log(Level.INFO, "getting proof size for ADS ID: "+Utils.byteArrayAsHexString(adsId));
		ProveADSRootRequest request = Request.createProveADSRootRequest(adsId);
		try {
			// request a proof
			// and record the length
			byte[] proof = this.server.getRequestHandler().proveADSRoot(request.toByteArray());
			
			int rawProofSize = proof.length;
			
			ProveADSRootResponse proofResponse = Request.parseProveADSResponse(proof);
			int sizeUpdate = proofResponse.getProof().getLastUpdate().getSerializedSize();
			int nSignatures = proofResponse.getProof().getLastUpdate().getSignaturesCount();
			int sizeSignatures = proofResponse.getProof().getLastUpdate().getSignaturesList().stream().mapToInt(x -> x.size()).sum();
			int sizeUpdateProof = proofResponse.getProof().getLastUpdatedProof().getSerializedSize();
			int sizeFreshnessProof = 0;
			int sizeFreshnessProofNoCacheOptimization = 0;
			MPTDictionaryPartial fullPath = MPTDictionaryPartial.deserialize(proofResponse.getProof().getLastUpdatedProof());
			for(MerklePrefixTrie mpt : proofResponse.getProof().getFreshnessProofList()) {
				sizeFreshnessProof+= mpt.getSerializedSize();
				// calculate the size required to have sent the actual full path 
				// rather than just the updates (for benchmarking purposes)
				fullPath.processUpdates(mpt);
				sizeFreshnessProofNoCacheOptimization += fullPath.serialize().getSerializedSize();
			}
			return new ProofSize(rawProofSize, sizeUpdate, nSignatures, sizeSignatures,
					sizeUpdateProof, sizeFreshnessProof, 
					sizeFreshnessProofNoCacheOptimization);
			
		} catch (RemoteException | InvalidSerializationException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static void main(String[] args) {
		/**
		 * TEST PARAMETERS
		 */
		final int batchSize = 10000;
		final int nUpdateBatches = 10;
		
		
		File dataf = new File(System.getProperty("user.dir") + "/benchmarks/test-data");
		StartingData data = StartingData.loadFromFile(dataf);
		// StartingData data2 = new StartingData(1500, 2, 1000000, CryptographicDigest.hash("data".getBytes()));
		
		ProofSizeBenchmark benchMedium = new ProofSizeBenchmark(data, batchSize);
		String mediumTest = System.getProperty("user.dir")+"/benchmarks/proof-sizes/data/"+"proof_size_benchmark.csv";
		benchMedium.runProofSizeBenchmark(nUpdateBatches, mediumTest);
		
	}
}
