package server;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.time.LocalDateTime;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
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
public class BVerifyServerUpdateApplier implements Runnable {
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
	
	private boolean shutdown;
	
	public BVerifyServerUpdateApplier(ReadWriteLock lock, BlockingQueue<PerformUpdateRequest> updates, 
			ADSManager adsManager, 
			int batchSize) {
		this.lock = lock;
		this.updates = updates;
		this.adsManager = adsManager;
		this.TARGET_BATCH_SIZE = batchSize;
		this.totalUpdates = 0;
		this.uncommittedUpdates = 0;
		this.shutdown = false;

		
		try {
			// process any initializing updates - if any!
			int initializingUpdates = 0;
			logger.log(Level.INFO, "... processing "+this.updates.size()+" initial updates");
			while(!this.updates.isEmpty()) {
				PerformUpdateRequest request = this.updates.take();
				this.adsManager.stageUpdate(request);
				initializingUpdates++;
				if(initializingUpdates % 1000000 == 0) {
					logger.log(Level.INFO, "..."+initializingUpdates+" initialized");
				}
				logger.log(Level.FINE, "initializing update #"+initializingUpdates);
			}
			logger.log(Level.INFO, "doing initial commit!");
			this.adsManager.commit();			
			logger.log(Level.INFO, "initialized "+initializingUpdates
					+" ADS_IDs [at "+LocalDateTime.now()+"]");
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
		
		
	}
	
	/**
	 * Call this method to safely shutdown the update applier thread
	 */
	public void setShutdown() {
		this.shutdown = true;
	}
	
	@Override
	public void run() {
		try {
			while(!this.shutdown) {
				// we use poll here to make sure that the shutdown condition is checked 
				// at least once a second
				PerformUpdateRequest updateRequest = this.updates.poll(1, TimeUnit.SECONDS);
				if(updateRequest == null) {
					continue;
				}
				this.adsManager.stageUpdate(updateRequest);
				
				uncommittedUpdates++;
				totalUpdates++;
				logger.log(Level.FINE, "staging update #"+totalUpdates);
				
				if(this.uncommittedUpdates % 1000 == 0) {
					logger.log(Level.INFO, "... batched currently: "+this.uncommittedUpdates);
				}
				
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
					logger.log(Level.INFO, "starting commit");
					long startTime = System.currentTimeMillis();
					this.adsManager.commit();
					long endTime = System.currentTimeMillis();
					this.lock.writeLock().unlock();
					long duration = endTime - startTime;
					NumberFormat formatter = new DecimalFormat("#0.000");
					String timeTaken = formatter.format(duration / 1000d)+ " seconds";
					logger.log(Level.INFO, "committed "+uncommittedUpdates+" updates in "+timeTaken);
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
