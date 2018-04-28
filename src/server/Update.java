package server;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import pki.Account;
import serialization.BVerifyAPIMessageSerialization.Request;

public class Update {

	private final Set<Account> sendTo;
	private final Request request;

	public Update(Set<Account> sendTo, Request request) {
		this.sendTo = sendTo;
		this.request = request;		
	}
	
	public Request getRequest() {
		return this.request;
	}

	public Set<Account> sendRequestTo() {
		return sendTo;
	}

	public Set<Map.Entry<byte[], byte[]>> getUpdatedKeyValues() {
		Set<Map.Entry<byte[], byte[]>> kvtoadd = new HashSet<>();
		return kvtoadd;
	}

}
