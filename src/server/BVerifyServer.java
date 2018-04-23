package server;

import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolServerAPI;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import serialization.BVerifyAPIMessageSerialization.*;
import serialization.MptSerialization.MerklePrefixTrie;

public class BVerifyServer implements BVerifyProtocolServerAPI {
	
	/**
	 * Components
	 */
	
	/**
	 * Actual ADSes - stored as
	 */
	
	// authentication information
	// 
	private MPTDictionaryFull currentAuthenticationInformation;
	
	// we also store changes 
	// index = commitment #, value = changes
	private List<MPTDictionaryDelta>	deltas;
	
	// changes are batched for efficiency 
	// we keep track of all requests 
	// and try to apply them all at once
	private List<IssueReceiptRequest> issueRequests;
	private List<RedeemReceiptRequest> redeemRequests;
	private List<TransferReceiptRequest> transferRequests;
	
	public BVerifyServer() {
		this.currentAuthenticationInformation = new MPTDictionaryFull();
	}

	@Override
	public void startIssueReceipt(byte[] requestIssueMessage) {
		try {
			IssueReceiptRequest request = IssueReceiptRequest.parseFrom(requestIssueMessage);
			this.issueRequests.add(request);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void startRedeemReceipt(byte[] requestRedeemMessage) {
		try {
			RedeemReceiptRequest request = RedeemReceiptRequest.parseFrom(requestRedeemMessage);
			this.redeemRequests.add(request);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void startTransferReceipt(byte[] requestTransferMessage) {
		try {
			TransferReceiptRequest request = TransferReceiptRequest.parseFrom(requestTransferMessage);
			this.transferRequests.add(request);
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
	}

	@Override
	public byte[] getUpdates(byte[] updateRequest) {
		try {
			GetUpdatesRequest request = GetUpdatesRequest.parseFrom(updateRequest);
			
			// parse the key hashes
			List<byte[]> keyHashes = new ArrayList<>();
			List<ByteString> keyHashesByteStrings = request.getKeyHashesList();
			for(ByteString keyHashByteString : keyHashesByteStrings) {
				keyHashes.add(keyHashByteString.toByteArray());
			}
			Updates.Builder updates = Updates.newBuilder();
			
			// go through each commitment 
			int startingFrom = request.getFromCommitNumber();
			for(int commitmentNumber = startingFrom ; commitmentNumber < this.deltas.size();
					commitmentNumber++) {
				// get the changes
				MPTDictionaryDelta delta = this.deltas.get(commitmentNumber);
				// and calculate the updates
				MerklePrefixTrie update = delta.getUpdatesKeyHashes(keyHashes);
				updates.addUpdate(update);
			}
			return updates.build().toByteArray();
			
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
		return null;
	}

}
