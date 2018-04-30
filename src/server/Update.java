package server;

import java.util.Set;

import serialization.BVerifyAPIMessageSerialization.RequestADSUpdates;

public class Update {

	private final Set<ADSModification> adsModifications;
	private final RequestADSUpdates signedRequest;

	public Update(Set<ADSModification> modifications, RequestADSUpdates signedRequest) {
		this.adsModifications = modifications;
		this.signedRequest = signedRequest;		
	}
	
	public RequestADSUpdates getSignedRequest() {
		return this.signedRequest;
	}

	public Set<ADSModification> getADSModifications() {
		return this.adsModifications;
	}

}
