package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.ripe.hadoop.pcap.packet.HttpPacket;
import net.ripe.hadoop.pcap.packet.Packet;

public class HttpPcapReader extends PcapReader{
	public static final Log LOG = LogFactory.getLog(HttpPcapReader.class);

	public static final int HTTP_PORT = 80;

	public HttpPcapReader(DataInputStream is) throws IOException {
		super(is);
	}

	@Override
	protected Packet createPacket() {
		LOG.debug("--- createPacket ---");
		return new HttpPacket();
	}

	//Only process http packages that contain value in payload
	@Override
	protected void processPacketPayload(Packet packet, byte[] payload) {
		
		HttpPacket httpPacket = (HttpPacket)packet;
		String s = new String(payload);
		
		if ((HTTP_PORT == (Integer)packet.get(Packet.DST_PORT)) && (PROTOCOL_TCP == (String)packet.get(Packet.PROTOCOL)) && (!(s.isEmpty()))){
			try {	
				s = s.replace("\n", "").replace("\r", "");
				httpPacket.put(HttpPacket.GET, StringUtils.substringBetween( s, "GET ", "Host"));
				httpPacket.put(HttpPacket.HOST, StringUtils.substringBetween( s, "Host: ", "User-Agent"));
				httpPacket.put(HttpPacket.USER_AGENT, StringUtils.substringBetween( s, "User-Agent: ", "Accept"));
				httpPacket.put(HttpPacket.ACCEPT, StringUtils.substringBetween( s, "Accept: ", "Accept-Language"));
				httpPacket.put(HttpPacket.ACCEPT_LANGUAGE, StringUtils.substringBetween( s, "Accept-Language: ", "Accept-Encoding"));
				httpPacket.put(HttpPacket.ACCEPT_ENCODING, StringUtils.substringBetween( s, "Accept-Encoding: ", "Accept-Charset"));
				httpPacket.put(HttpPacket.ACCEPT_CHARSET, StringUtils.substringBetween( s, "Accept-Charset: ", "Keep-Alive"));
				httpPacket.put(HttpPacket.KEEP_ALIVE, StringUtils.substringBetween( s, "Keep-Alive: ", "Connection"));
				httpPacket.put(HttpPacket.CONNECTION, StringUtils.substringBetween( s, "Connection: ", "Referer"));
				httpPacket.put(HttpPacket.REFERER, StringUtils.substringBetween( s, "Referer: ", ""));
			} catch (Exception e) {
				// If we cannot decode a http packet we ignore it
			}
		}
	}
}