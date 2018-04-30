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
	
	public byte[] approveRequest(byte[] requestMessage) throws RemoteException;
	
	public boolean approveEchoBenchmark(boolean response) throws RemoteException;
	
	public byte[] approveSigEchoBenchmark(byte[] messageToSign) throws RemoteException;
	
}
