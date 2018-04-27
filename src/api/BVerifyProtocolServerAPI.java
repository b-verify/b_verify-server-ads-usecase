package api;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * The API exposed by the b_verify server to the b_verify clients
 * 
 * @author henryaspegren
 *
 */
public interface BVerifyProtocolServerAPI extends Remote {
	
	/**
	 * Invoked by a client remotely on the server to 
	 * request that a receipt be issued. If this method
	 * returns true then the receipt has been scheduled
	 * to be issued and the server promises to invoke  
	 * approveReceiptIssue( - ) on the client at a later point
	 * to request that the client approve the issued receipt
	 * @param requestIssueMessage a serialized request 
	 * for the server to issue a receipt (see 
	 * 	IssueReceiptRequest in bverifyprotocol.proto)
	 * @return true if the receipt has been scheduled to be issued
	 * and the server will contact the client in the future 
	 * with a proof
	 */
	public boolean startIssueReceipt(byte[] requestIssueMessage)  throws RemoteException;
	
	/**
	 * Invoked by a client remotely on the server to 
	 * request that a receipt be redeemed. This method returns 
	 * immediately. If this method
	 * returns true then the receipt has been scheduled
	 * to be issued and the server promises to invoke  
	 * approveRedeemReceipt( - ) on the client at a later point
	 * to request that the client approve the redeemed receipt
	 * @param requestRedeemMessage a serialized request 
	 * for the server to redeem a receipt (see 
	 *  RedeemReceiptRequest in bverifyprotocol.proto)
	 * @return true if the receipt has been scheduled to be redeemed
	 * and the server will contact the client in the future with
	 * a proof
	*/
	public boolean startRedeemReceipt(byte[] requestRedeemMessage)  throws RemoteException;
	
	/**
	 * Invoked by a client remotely on the server to 
	 * request that a receipt be transferred. This method returns
	 * immediately. The server promises to invoke 
	 * approveTransferRequest( - ) on both clients at a later point
	 * to request that the client approve the transfer request
	 * @param requestTransferMessage a serialized request 
	 * for the server to transfer a receipt (see 
	 * 	TransferReceiptRequest in bverifyprotocol.proto)
	 * @return true if the receipt has been scheduled to be transferred
	 * and the server will contact the client in the future 
	 * with a proof
	*/
	public boolean startTransferReceipt(byte[] requestTransferMessage)  throws RemoteException;
	
	/**
	 * Invoked by a client remotely on the server to request
	 * the server to send (client specific) updates. This method
	 * returns a serialized set of updates
	 * @param updateRequest - a serialized request for updates 
	 * (see GetUpdatesRequest in bverifyprotocol.proto)
	 * @return a serialized response containing updates 
	 * (see Updates in bverifyprotocol.proto)
	 */
	public byte[] getUpdates(byte[] updateRequest)  throws RemoteException;
	
}
