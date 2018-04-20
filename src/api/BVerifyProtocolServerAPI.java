package api;

import java.rmi.Remote;

public interface BVerifyProtocolServerAPI extends Remote {
	
	public void startIssueReceipt(byte[] requestIssueMessage);
	
	public void startRedeemReceipt(byte[] requestRedeemMessage);
	
	public void startTransferReceipt(byte[] requestTransferMessage);
	
	public byte[] getUpdates(byte[] updateRequest);
}
