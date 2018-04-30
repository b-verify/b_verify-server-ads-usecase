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
	
	public boolean submitUpdates(byte[] adsUpdates) throws RemoteException;
	
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
