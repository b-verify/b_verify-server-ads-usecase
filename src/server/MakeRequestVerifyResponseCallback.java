package server;

import java.util.concurrent.Callable;

import api.BVerifyProtocolClientAPI;
import pki.Account;
import rmi.ClientProvider;


/**
 * This class is responsible for actually making requests to 
 * clients and verifying the responses. 
 * 
 * Since the server will want to make requests to 
 * many clients simultaneously this class
 * can be run in its own thread!
 * 
 * @author henryaspegren
 *
 */
public class MakeRequestVerifyResponseCallback implements Callable<Boolean> {
	
	private final Update request;
	private final Account sendTo;
	private final ClientProvider rmi;

	
	public MakeRequestVerifyResponseCallback(final Account sendTo, 
			final Update r, final ClientProvider rmi) {
		this.request = r;
		this.sendTo = sendTo;
		this.rmi = rmi;
	}

	@Override
	public Boolean call() throws Exception {
		// lookup the client 
		BVerifyProtocolClientAPI stub = this.rmi.getClient(this.sendTo);
		
		// make the request
		// byte[] resp = stub.approveRequest(this.request.getRequest().toByteArray());
		// get the response
		// Response response = Response.parseFrom(resp);
		
		// check the signatures
		
		return Boolean.valueOf(true);		
	}

}
