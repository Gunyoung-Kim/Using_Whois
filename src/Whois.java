import java.net.*;
import java.io.*;

public class Whois {
	public final static int DEFAULT_PORT = 43;
	public final static String DEFAULT_HOST = "whois.internic.net";
	
	private int port = DEFAULT_PORT;
	private InetAddress host;
	
	// 생성자 모임
	public Whois(InetAddress host, int port) {
		this.host = host;
		this.port = port;
	}
	
	public Whois(int port) throws UnknownHostException {
		this(DEFAULT_HOST, DEFAULT_PORT);
	}
	
	public Whois(String hostname, int port) throws UnknownHostException {
		this.host = InetAddress.getByName(hostname);
		this.port = port;
	}
	
	public Whois(String hostname) throws UnknownHostException {
		this.host = InetAddress.getByName(hostname);
		this.port = DEFAULT_PORT;
	}
	
	public Whois() throws UnknownHostException {
		this(DEFAULT_HOST, DEFAULT_PORT);
	}
	
	public enum SearchFor {
		ANY(""), NETWORK("Network"),PERSON("Person"),HOST("Host"),DOMAIN("Domain")
		,ORGANIZATION("Organization"),GROUP("Group"),GATEWAY("GateWay"),ASN("ASN");
		private String label;
		
		private SearchFor(String label) {
			this.label = label;
		}
	}
	
	public enum SearchIn {
		ALL(""), NAME("Name"), MAILBOX("Mailbox"), HANDLE("!");
		
		private String label;
		
		private SearchIn(String label) {
			this.label = label;
		}
	}
	
	public String lookUpNames(String target, SearchFor category, SearchIn group, boolean exactMatch) throws IOException {
		String suffix = "";
		if(!exactMatch) suffix = ".";
		
		String prefix = category.label + " " + group.label;
		String query = prefix + target + suffix;
		
		Socket socket = new Socket();
		try {
			SocketAddress address = new InetSocketAddress(this.host, this.port);
			socket.connect(address);
			Writer out = new OutputStreamWriter(socket.getOutputStream(),"ASCII");
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(),"ASCII"));
			out.write(query+ "\r\n");
			out.flush();
			
			StringBuilder response = new StringBuilder();
			String theLine = null;
			while((theLine = in.readLine()) != null) {
				response.append(theLine);
				response.append("\r\n");
			}
			return response.toString();
		} finally {
			socket.close();
		}
	}
	
	public InetAddress getHost() {
		return this.host;
	}
	
	public void setHost(String host) throws UnknownHostException {
		this.host = InetAddress.getByName(host);
	}
	
}
