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
	
	/*
	 * These methods are the b_verify client API
	 */
	
	public byte[] approveRequest(byte[] requestMessage) throws RemoteException;
	
	
	/*
	 * These methods are not part of the secure API
	 * 	and are used only for benchmarking and testing. 
	 */
	public void recieveNewCommitment(byte[] commitment) throws RemoteException;
	
	public boolean approveEchoBenchmark(boolean response) throws RemoteException;
	
	public byte[] approveSigEchoBenchmark(byte[] messageToSign) throws RemoteException;
	
}
