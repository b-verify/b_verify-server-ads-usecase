package api;

import java.rmi.Remote;

public interface BVerifyProtocolClientAPI extends Remote {
	
	public byte[] approveReceiptIssue(byte[] approveIssueMessage);
	
	public byte[] approveReceiptRedeem(byte[] approveRedeemMessage);
	
	public byte[] approveReceiptTransfer(byte[] approveTransferMessage);
	
}
