package server;

import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;

public class BVerifyServerUpdateApplier extends Thread {
	private static final Logger logger = Logger.getLogger(BVerifyServerUpdateApplier.class.getName());

	/**
	 * Parameters - batching, impact performance
	 */
	private final int BATCH_SIZE;
	// TODO also add a timeout so that things eventually get
	//			committed
	
	/**
	 * Shared data!
	 */
	private final BlockingQueue<PerformUpdateRequest> updates;
	private final ADSManager adsManager;
	
	public BVerifyServerUpdateApplier(BlockingQueue<PerformUpdateRequest> updates, 
			ADSManager adsManager, 
			int batchSize) {
		this.updates = updates;
		this.adsManager = adsManager;
		this.BATCH_SIZE = batchSize;
	}

	@Override
	public void run() {
		try {
			int totalUpdates = 0;
			int uncommittedUpdates = 0;
			while(true) {
				// block and wait for an update
				PerformUpdateRequest updateRequest = this.updates.take();
				//go through and apply the updates
				for(ADSModification modification : updateRequest.getUpdate().getModificationsList()) {
					this.adsManager.update(modification.getAdsId().toByteArray(), 
							modification.getNewValue().toByteArray());
				}
				uncommittedUpdates++;
				totalUpdates++;
				logger.log(Level.INFO, "applying update #"+totalUpdates);
				// only commit once batch is large enough
				if(uncommittedUpdates >= BATCH_SIZE) {
					byte[] newCommitment = this.adsManager.commit();
					logger.log(Level.INFO, "committing "+uncommittedUpdates+" updates");
					uncommittedUpdates = 0;
				}
			}
		} catch(InterruptedException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "something is wrong...shutdown");
			throw new RuntimeException(e.getMessage());
		}
	}
	
}
