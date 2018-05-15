package bench;

public class ProofSize{
	
	private final int rawProofSize;
	private final int updateSize; 
	private final int updateProofSize;
	private final int freshnessProofSize;
	
	public ProofSize(int raw, int update, int updateProof, int freshProof) {
		this.rawProofSize = raw;
		this.updateSize = update;
		this.updateProofSize = updateProof;
		this.freshnessProofSize = freshProof;
	}

	public int getRawProofSize() {
		return rawProofSize;
	}

	public int getUpdateSize() {
		return updateSize;
	}

	public int getUpdateProofSize() {
		return updateProofSize;
	}

	public int getFreshnessProofSize() {
		return freshnessProofSize;
	}
	
}
