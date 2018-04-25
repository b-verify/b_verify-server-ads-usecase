package client;

import api.BVerifyProtocolClientAPI;

/**
 * For benchmarking and testing purposes 
 * we include a simple implementation of a 
 * b_verify client 
 * 
 * @author henryaspegren
 *
 */
public class MockClient implements BVerifyProtocolClientAPI{

	@Override
	public byte[] approveReceiptIssue(byte[] approveIssueMessage) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] approveReceiptRedeem(byte[] approveRedeemMessage) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] approveReceiptTransfer(byte[] approveTransferMessage) {
		// TODO Auto-generated method stub
		return null;
	}

}
