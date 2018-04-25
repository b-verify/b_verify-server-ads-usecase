package server;

import java.util.concurrent.Callable;

import api.BVerifyProtocolClientAPI;
import crpyto.CryptographicSignature;
import pki.Account;
import rmi.ClientProvider;
import serialization.BVerifyAPIMessageSerialization.Signature;


/**
 * This class is responsible for actually making requests to 
 * clients and verifying the responses. 
 * 
 * Since the server will want to make requests to 
 * many clients simultaneously this class
 * can be run in its own thread!
 * 
 * @author henryaspegren
 *
 */
public class MakeRequestVerifyResponseCallback implements Callable<Boolean> {
	
	private final byte[] requestMessage;
	private final byte[] commitmentToBeSigned;

	// this is ugly and should be replaced
	private enum TYPE {ISSUE, REDEEM, TRANSFER};
	private final TYPE messageType;

	private final Account sendTo;
	private final ClientProvider provider;

	
	public MakeRequestVerifyResponseCallback(final byte[] requestMessage, final Account sendTo, 
			final byte[] commitmentToBeSigned, final Request r, final ClientProvider provider) {
		this.requestMessage = requestMessage;
		this.commitmentToBeSigned = commitmentToBeSigned;
		this.sendTo = sendTo;
		this.provider = provider;
		if(r instanceof TransferRequest) {
			this.messageType = TYPE.TRANSFER;
		}else if (r instanceof IssueRequest) {
			this.messageType = TYPE.ISSUE;		
		}else if (r instanceof RedeemRequest) {
			this.messageType = TYPE.REDEEM;
		}else {
			throw new RuntimeException("not a valid request");
		}
	}

	@Override
	public Boolean call() throws Exception {
		// lookup the client 
		BVerifyProtocolClientAPI stub = this.provider.getClient(this.sendTo);
		byte[] resp = null;
		// make the request
		switch (this.messageType){
		case ISSUE:
			resp = stub.approveReceiptIssue(this.requestMessage);
		case REDEEM:
			resp = stub.approveReceiptRedeem(this.requestMessage);
		case TRANSFER:
			resp = stub.approveReceiptTransfer(this.requestMessage);
		}
		if(resp == null) {
			return Boolean.FALSE;
		}
		// verify the signature
		Signature sig = Signature.parseFrom(resp);
		byte[] sigBytes = sig.getSignature().toByteArray();
		boolean hasSigned = CryptographicSignature.verify(this.commitmentToBeSigned, 
				sigBytes, this.sendTo.getPublicKey());
		return Boolean.valueOf(hasSigned);		
	}

}
