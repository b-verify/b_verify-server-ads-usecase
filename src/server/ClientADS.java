package server;

import java.util.Set;

import mpt.set.AuthenticatedSetServer;
import pki.Account;

public class ClientADS {

	private final Set<Account> owners;
	private final byte[] id;
	private final AuthenticatedSetServer ads;
	
	public ClientADS(Set<Account> owners, byte[] id, AuthenticatedSetServer ads) {
		this.owners = owners;
		this.id = id;
		this.ads = ads;
	}
	
	public Set<Account> getOwners(){
		// mutable reference!!!
		return this.owners;
	}
	
	public byte[] id() {
		return this.id.clone();
	}
	
}
