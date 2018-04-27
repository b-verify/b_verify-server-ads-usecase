package rmi;

import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import api.BVerifyProtocolClientAPI;
import pki.Account;

public class ClientProvider {
	
	public static String SERVER_NAME = "SERVER";
	
	private Registry registry;
	
	public ClientProvider(String host, int port) {
		try {
			this.registry = LocateRegistry.getRegistry(host, port);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	public void bind(String name, Remote robj) {
		try {
			this.registry.rebind(name, robj);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
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
