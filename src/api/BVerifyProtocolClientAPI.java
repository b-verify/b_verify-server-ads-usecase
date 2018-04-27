package api;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * The API exposed by b_verify clients to the b_verify server
 * 
 * @author Henry Aspegren
 *
 */
public interface BVerifyProtocolClientAPI extends Remote {
	
	/**
	 * Invoked remotely by the server to request that a client 
	 * approve an issued receipt. If the client approves, 
	 * she releases a signature.
	 * @param approveIssueMessage a serialized proof showing 
	 * the issued receipt (see ReceiptIssueApprove in
	 * bverifyprotocolapi.proto)
	 * @return a serialized witness and signature (see Signature in
	 * bverifyprotocolapi.proto)
	 */
	public byte[] approveReceiptIssue(byte[] approveIssueMessage) throws RemoteException;
	
	/**
	 * Invoked remotely by the server to request that a client 
	 * approve a redeemed receipt. If the client approves, 
	 * she releases a signature
	 * @param approveRedeemMessage a serialized proof showing 
	 * the redeemed receipt (see ReceiptRedeemApprove in
	 * bverifyprotocolapi.proto)
	 * @return a serialized witness and signature (see Signature in
	 * bverifyprotocolapi.proto)
	 */
	public byte[] approveReceiptRedeem(byte[] approveRedeemMessage) throws RemoteException;
	
	/**
	 * Invoked remotely by the server to request that a client 
	 * approve a receipt transfer. If the client approves,
	 * she releases a signature
	 * @param approveTransferMessage a serialized proof showing 
	 * the transferred receipt (see ReceiptTransferApprove in 
	 * bverfiyprotocolapi.proto)
	 * @return a serialized witness and signature (see Signature in 
	 * bverifyprotocolapi.proto)
	 */
	public byte[] approveReceiptTransfer(byte[] approveTransferMessage) throws RemoteException;
	
	
	public boolean approveEchoBenchmark(boolean response) throws RemoteException;
	
	public byte[] approveSigEchoBenchmark(byte[] messageToSign) throws RemoteException;
	
}
