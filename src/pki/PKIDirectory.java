package pki;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class PKIDirectory {
	
	private final String base;
	
	public PKIDirectory(String base) {
		this.base = base;
	}
	
	public Account getAccount(UUID id) {
		return Account.loadFromFile(base+id.toString());
	}
	
	public Account getAccount(String uuidString) {
		UUID uuid = UUID.fromString(uuidString);
		return this.getAccount(uuid);
	}
	
	public List<UUID> listAccounts(){
		File[] files = new File(base).listFiles();
		List<UUID> uuids = new ArrayList<>();
		for (File file : files) {
		    if (file.isFile()) {
		    	uuids.add(UUID.fromString(file.getName()));
		    }
		}
		return uuids;
	}
	
	public static void main(String[] args) {
		PKIDirectory pki = new PKIDirectory("/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/pki/");
		System.out.println(pki.listAccounts());
	}
}
