package server;

import java.util.concurrent.Callable;

import pki.Account;

public class MakeRequestCallback implements Callable<Boolean> {
	
	private final byte[] message;
	private final Account sendTo;
	
	
	public MakeRequestCallback(byte[] message, Account sendTo) {
		this.message = message;
		this.sendTo = sendTo;
	}

	@Override
	public Boolean call() throws Exception {
		// actually make the call via RMI
		return true;
	}

}
