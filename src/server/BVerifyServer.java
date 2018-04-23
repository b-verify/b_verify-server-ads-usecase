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
	 * Client ADSes - stored on disk
	 */
	private final ClientADSManager clientadsManager;
	
	/**
	 * Server (Authentication) ADSes - stored in memory
	 */
	private final ServerADSManager serveradsManager;
		
	/**
	 * Changes to be applied.
	 * We batch changes for efficiency 
	 * we keep track of all requests 
	 * and try to apply them all at once.
	 */
	private List<IssueReceiptRequest> issueRequests;
	private List<RedeemReceiptRequest> redeemRequests;
	private List<TransferReceiptRequest> transferRequests;
	
	public BVerifyServer(String base) {
		this.clientadsManager = new ClientADSManager(base+"/client-ads/");
		this.serveradsManager = new ServerADSManager(base+"/server-ads/");
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
			int from = request.getFromCommitNumber();
			return this.serveradsManager.getUpdate(from, keyHashes);
			
		} catch (InvalidProtocolBufferException e) {
			e.printStackTrace();
		}
		return null;
	}

}
