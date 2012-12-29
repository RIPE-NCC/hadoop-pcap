package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.IOException;

import net.ripe.hadoop.pcap.packet.HttpPacket;
import net.ripe.hadoop.pcap.packet.Packet;

public class HttpPcapReader extends PcapReader{
	public static final int HTTP_PORT = 80;
	public static final String PROTOCOL = "TCP";

	public HttpPcapReader(DataInputStream is) throws IOException {
		super(is);
	}

	@Override
	protected Packet createPacket() {
		System.out.println("--- createPacket ---");
		return new HttpPacket();
	}

	//Only process http packages that contain value in payload
	@Override
	protected void processPacketPayload(Packet packet, byte[] payload) {
		
		HttpPacket httpPacket = (HttpPacket)packet;
		String s = new String(payload);
		
		if ((HTTP_PORT == (Integer)packet.get(Packet.DST_PORT)) && (PROTOCOL == (String)packet.get(Packet.PROTOCOL)) && (!(s.isEmpty()))){
			try {	
				s = s.replace("\n", "").replace("\r", "");
				httpPacket.put(HttpPacket.GET, substringBetween( s, "GET ", "Host"));
				httpPacket.put(HttpPacket.HOST, substringBetween( s, "Host: ", "User-Agent"));
				httpPacket.put(HttpPacket.USER_AGENT, substringBetween( s, "User-Agent: ", "Accept"));
				httpPacket.put(HttpPacket.ACCEPT, substringBetween( s, "Accept: ", "Accept-Language"));
				httpPacket.put(HttpPacket.ACCEPT_LANGUAGE, substringBetween( s, "Accept-Language: ", "Accept-Encoding"));
				httpPacket.put(HttpPacket.ACCEPT_ENCODING, substringBetween( s, "Accept-Encoding: ", "Accept-Charset"));
				httpPacket.put(HttpPacket.ACCEPT_CHARSET, substringBetween( s, "Accept-Charset: ", "Keep-Alive"));
				httpPacket.put(HttpPacket.KEEP_ALIVE, substringBetween( s, "Keep-Alive: ", "Connection"));
				httpPacket.put(HttpPacket.CONNECTION, substringBetween( s, "Connection: ", "Referer"));
				httpPacket.put(HttpPacket.REFERER, substringBetween( s, "Referer: ", ""));
			} catch (Exception e) {
				// If we cannot decode a http packet we ignore it
			}
		}
	}
	
	public static String substringBetween(String str, String open, String close) {
	      if (str == null || open == null || close == null) {
	          return null;
	      }
	      int start = str.indexOf(open);
	      int end;
	      if (start != -1) {
	    	  if (close == ""){
	    		  end = str.length();
	    	  }
	    	  else{
	    		  end = str.indexOf(close, start + open.length());
	    	  }
	          if (end != -1) {
	              return str.substring(start + open.length(), end);
	          }
	      }
	      return null;
	  }
}