package server;

import java.util.concurrent.BlockingQueue;

public class BVerifyServerUpdateApplier extends Thread {

	
	private static final int BATCH_SIZE = 1;
	private final BlockingQueue<Update> updates;
	private final ADSManager adsManager;
	
	public BVerifyServerUpdateApplier(BlockingQueue<Update> updates, ADSManager adsManager) {
		this.updates = updates;
		this.adsManager = adsManager;
	}

	@Override
	public void run() {
		try {
			int uncommittedChanges = 0;
			while(true) {
				// block and wait for an update
				Update update = this.updates.take();
				//go through and apply the updates
				for(ADSModification modification : update.getADSModifications()) {
					this.adsManager.update(modification.getADSKey(), modification.getADSValue());
					uncommittedChanges++;
				}
				// only commit once batch is large enough
				if(uncommittedChanges > BATCH_SIZE) {
					byte[] newCommitment = this.adsManager.commit();
					System.out.println(newCommitment);
					uncommittedChanges = 0;
				}
			}
		} catch(InterruptedException e) {
			e.printStackTrace();
		}
	}
	
}
