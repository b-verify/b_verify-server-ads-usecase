package bench;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.List;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import api.BVerifyProtocolClientAPI;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import mpt.core.InsufficientAuthenticationDataException;
import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.dictionary.AuthenticatedDictionaryClient;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import rmi.ClientProvider;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModificationRequest;
import serialization.generated.BVerifyAPIMessageSerialization.GetUpdatesRequest;
import serialization.generated.BVerifyAPIMessageSerialization.RequestADSUpdates;
import serialization.generated.BVerifyAPIMessageSerialization.Signature;
import serialization.generated.BVerifyAPIMessageSerialization.Updates;
import serialization.generated.MptSerialization.MerklePrefixTrie;

public class MockSimpleClient implements BVerifyProtocolClientAPI {
	
	// the account of this mock client
	private final Account account;

	// for the simple client, the client has only a single ADS
	// and we just keep the key (hide the ADS)
	
	private final byte[] adsKey;
	private AuthenticatedDictionaryClient authAds;
	private final byte[] adsUpdateRequest;
	private final byte[] getUpdatesRequest;
	private int commitmentNumber;
	
	// provides rmi interface for 
	// invoking methods remotely on the server
	private ClientProvider rmi;
	
	public MockSimpleClient(Account a, String base, String host, int port) {
		this.account = a;
		List<byte[]> adsKeys = a.getADSKeys().stream().collect(Collectors.toList());
		assert adsKeys.size() == 1;
		this.adsKey = adsKeys.get(0);
		this.bind(host, port);
		try {
			byte[] authAdsBytes = this.rmi.getServer().getAuthenticationProof(adsKeys);
			this.authAds = MPTDictionaryPartial.deserialize(authAdsBytes);
			byte[] currentValue = this.authAds.get(this.adsKey);
			this.commitmentNumber = 0;
			System.out.println("LOADED current value: "+Utils.byteArrayAsHexString(currentValue)+
					"| commitment: "+Utils.byteArrayAsHexString(this.authAds.commitment()));
		} catch (RemoteException | InvalidSerializationException | InsufficientAuthenticationDataException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
		
		// generate a request to be sent to the server to update 
		// the ADS
		byte[] adsNewValue = CryptographicDigest.hash("updated".getBytes());
		this.adsUpdateRequest = this.generateADSUpdateRequest(adsNewValue).toByteArray();
		this.getUpdatesRequest = this.generateGetUpdatesRequest().toByteArray();
		System.out.println(this.account.getIdAsString()+" ready");
	}
	
	private void bind(String registryHost, int registryPort) {
		this.rmi = new ClientProvider(registryHost, registryPort);
		// bind this object
		BVerifyProtocolClientAPI clientAPI;
		try {
			clientAPI = (BVerifyProtocolClientAPI) UnicastRemoteObject.exportObject(this, 0);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
		this.rmi.bind(this.account.getIdAsString(), clientAPI);
	}
	
	private GetUpdatesRequest generateGetUpdatesRequest() {
		GetUpdatesRequest updateMsg = GetUpdatesRequest
				.newBuilder()
				.addKeys(ByteString.copyFrom(this.adsKey))
				.setFromCommitNumber(this.commitmentNumber)
				.build();
		return updateMsg;
	}
	
	private RequestADSUpdates generateADSUpdateRequest(byte[] newAdsValue) {
		ADSModificationRequest modification = ADSModificationRequest.newBuilder()
				.setAdsId(ByteString.copyFrom(this.adsKey))
				.setNewValue(ByteString.copyFrom(newAdsValue))
				.build();
		byte[] witness = CryptographicDigest.hash(modification.toByteArray());
		byte[] signature = CryptographicSignature.sign(witness, 
				this.account.getPrivateKey());
		RequestADSUpdates requestMsg = RequestADSUpdates
				.newBuilder()
				.addModifications(modification)
				.addSignatures(Signature
						.newBuilder()
						.setSignature(ByteString.copyFrom(signature)))
				.build();
		return requestMsg;
	}
	
	public void sendRequest() {
		System.out.println("sending update request for "+this.account.getIdAsString());
		try {
			boolean response = this.rmi.getServer().submitUpdates(this.adsUpdateRequest);
			System.out.println("response recieved for "+this.account.getIdAsString()+" response: "+response);
		} catch (RemoteException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public void getAndCheckUpdates() {
		try {
			byte[] update = this.rmi.getServer().getUpdates(this.getUpdatesRequest);
			Updates updateMsg = Updates.parseFrom(update);
			for(MerklePrefixTrie mptUpdate : updateMsg.getUpdateList()) {
				this.authAds.processUpdates(mptUpdate);
				System.out.println("update processed - new commitment : "+
						Utils.byteArrayAsHexString(this.authAds.commitment()));
			}
			System.out.println("all updates processed");
		} catch (RemoteException | InvalidProtocolBufferException | InvalidSerializationException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	@Override
	public void recieveNewCommitment(byte[] commitment) throws RemoteException {
		throw new RuntimeException("simple client does not support loading commitments");
	}

	@Override
	public byte[] approveRequest(byte[] requestMessage) {
		throw new RuntimeException("simple client does not support requests");
	}

	@Override
	public boolean approveEchoBenchmark(boolean response) {
		System.out.println("Client "+this.account+ " echo request recieved, responding");
		return response;
	}
	
	@Override 
	public byte[] approveSigEchoBenchmark(byte[] toSign) {
		System.out.println("Client "+this.account+ " sig echo request recieved, responding");
		byte[] sigBytes = CryptographicSignature.sign(toSign, this.account.getPrivateKey());
		Signature.Builder sig = Signature.newBuilder();
		sig.setSignature(ByteString.copyFrom(sigBytes));
		return sig.build().toByteArray();
	}
	
	@Override 
	public String toString() {
		return "<"+this.account.getIdAsString()+" - "+Utils.byteArrayAsHexString(this.adsKey)+">";
	}
}
