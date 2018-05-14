package server;

import java.time.LocalDateTime;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;

/**
 * This is a single threaded applier that 
 * stages updates. After TARGET_BATCH_SIZE updates 
 * have been performed, the applier thread freezes the 
 * handler by acquiring the write lock, applies all outstanding 
 * entries and commits them. 
 * @author henryaspegren
 *
 */
public class BVerifyServerUpdateApplier extends Thread {
	private static final Logger logger = Logger.getLogger(BVerifyServerUpdateApplier.class.getName());

	/**
	 * Parameters - batching, impact performance
	 */
	private int totalUpdates;
	private int uncommittedUpdates;
	private final int TARGET_BATCH_SIZE;
	// TODO also add a timeout so that things eventually get
	//			committed
	
	/**
	 * Shared data!
	 */
	private final ReadWriteLock lock;
	private final BlockingQueue<PerformUpdateRequest> updates;
	private final ADSManager adsManager;
	
	public BVerifyServerUpdateApplier(ReadWriteLock lock, BlockingQueue<PerformUpdateRequest> updates, 
			ADSManager adsManager, 
			int batchSize) {
		this.lock = lock;
		this.updates = updates;
		this.adsManager = adsManager;
		this.TARGET_BATCH_SIZE = batchSize;
		this.totalUpdates = 0;
		this.uncommittedUpdates = 0;

		
		try {
			// process initial updates
			int initializingUpdates = 0;
			while(!this.updates.isEmpty()) {
				PerformUpdateRequest request = this.updates.take();
				this.adsManager.stageUpdate(request);
				initializingUpdates++;
				logger.log(Level.INFO, "initializing update #"+initializingUpdates);
			}
			logger.log(Level.INFO, "doing initial commit!");
			this.adsManager.commit();
			logger.log(Level.INFO, "initialized: "+initializingUpdates
					+" [at "+LocalDateTime.now()+"]");
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
		
		
	}

	@Override
	public void run() {
		try {
			while(true) {
				// block and wait for an update
				
				PerformUpdateRequest updateRequest = this.updates.take();
				this.adsManager.stageUpdate(updateRequest);
				
				uncommittedUpdates++;
				totalUpdates++;
				logger.log(Level.FINE, "staging update #"+totalUpdates);
				
				// once we hit the batch size, trigger a commit
				// 
				if(this.uncommittedUpdates == this.TARGET_BATCH_SIZE) {
					// stop accepting requests by getting the WRITE LOCK
					this.lock.writeLock().lock();
					// drain any approved updates (since have lock, no more will get added,
					// but there may be some existing updates outstanding)
					while(!this.updates.isEmpty()) {
						PerformUpdateRequest request = this.updates.take();
						this.adsManager.stageUpdate(request);
						uncommittedUpdates++;
						totalUpdates++;
						logger.log(Level.FINE, "staging update #"+totalUpdates);
					}
					// once all outstanding updates are added
					// commit!
					this.adsManager.commit();
					this.lock.writeLock().unlock();
					logger.log(Level.INFO, "committing updates #"+uncommittedUpdates);
					logger.log(Level.INFO, "total updates: "+totalUpdates
							+" [at "+LocalDateTime.now()+"]");
					this.uncommittedUpdates = 0;
				}
			}
		} catch(InterruptedException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "something is wrong...shutdown");
			throw new RuntimeException(e.getMessage());
		}
	}
	
}
