package server;

import java.util.Map;

public class ADSModification {

	private final byte[] adsKey;
	private final byte[] adsValue;
		
	public ADSModification(byte[] adsKey, byte[] adsValue) {
		this.adsKey = adsKey;
		this.adsValue = adsValue;
	}
	
	public byte[] getADSKey() {
		return this.adsKey;
	}
	
	public byte[] getADSValue() {
		return this.adsValue;
	}	
	
	public Map.Entry<byte[], byte[]> getADSKeyValueUpdate(){
		return Map.entry(this.adsKey, this.adsValue);
	}
	
}
