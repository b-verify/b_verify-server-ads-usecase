package api;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

/**
 * The API exposed by the b_verify server to the b_verify clients
 * 
 * @author henryaspegren
 *
 */
public interface BVerifyProtocolServerAPI extends Remote {
	
	public byte[] performUpdate(byte[] adsUpdates) throws RemoteException;
		
	public byte[] proveADSRoot(byte[] adsRootRequest) throws RemoteException;
	
	// for testing only - these should be witnessed to Bitcoin using Catena!
	public List<byte[]> commitments() throws RemoteException;
	
}
