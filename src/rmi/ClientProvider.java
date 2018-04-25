package rmi;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.Registry;

import api.BVerifyProtocolClientAPI;
import pki.Account;

public class ClientProvider {
	
	private Registry registry;
	
	public BVerifyProtocolClientAPI getClient(Account client) {
		String id = client.getIdAsString();
		BVerifyProtocolClientAPI clientAPI;
		try {
			clientAPI = (BVerifyProtocolClientAPI) this.registry.lookup(id);
			return clientAPI;
		} catch (RemoteException | NotBoundException e) {
			return null;
		}
	}
	

}
