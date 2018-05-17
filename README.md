# b_verify Server

## Throughput Benchmark
To test server throughput we measure the amount of time to update a fraction of all of the data structures stored on the b_verify server and to request proofs that the update was performed from the server. 

To simulate a real deployment we create a medium sized b_verify server with 
``10^6 ADSes Total``
We will update 
``10% of all ADSes = 10^5 ADS updates``

To simulate mock clients we use 500 threads to send each of the update requests individually. The Java RMI interface begins to have problems at about >5 request per millisecond, so we introduce some random delay into when the client threads actually make the requests. Overall this will only increase these benchmarks, and it is probably possible by carefully tuning the timing to get even better results.

### Time To Request Updates
``95.404 seconds``
This is the time required for 10^5 separate clients to submit update request to the server, for the server to verify these requests and schedule it to be committed, and then to reply ACCEPTED to the client. 

### Time To Commit (on Server)
``1.675 seconds``
This is the time required for the server to commit a batch of updates and broadcast the commitment. During this period the server cannot accept new update requests.

### Time To Request Proofs 
``21.605 seconds``
This is the time required for each of the 10^5 separate clients to request a proof showing that the update was performed.

### Total Time 
``118.684 seconds or about 2 minutes``
Overall the complete process to update and verify 10% of the ADSes on a realistically sized serer is about 2 minutes.


## Proof Size Benchmark
To test proof sizes we measured how the size of the proof for an ADS_ROOT changes as updates to other ADSes are performed. 

To simulate a real deployment we again used a medium size b_verify server with 
``10^6 ADSes Total``
and again performed 
``10% of all ADSes = 10^5 ADS updates``
but this time we did each of the updates in batches of
``1% of all ADSes updated in each batch = 10^4 ADS update in each batch``
and measured the size of the proof after each update.

We split the proof size into the ``update`` portion: the signed update and a proof that the update was performed and the ``freshness`` portion: which is a proof that the update is fresh.

### Results
![picture](benchmarks/proof-sizes/proof_size.png) 


