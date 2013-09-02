package net.ripe.hadoop.pcap;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.LinkedList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseFactory;
import org.apache.http.impl.DefaultHttpRequestFactory;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.conn.DefaultClientConnection;
import org.apache.http.impl.io.AbstractSessionInputBuffer;
import org.apache.http.impl.io.AbstractSessionOutputBuffer;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.io.HttpMessageParser;
import org.apache.http.io.SessionInputBuffer;
import org.apache.http.io.SessionOutputBuffer;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;

import com.google.common.base.Joiner;

import net.ripe.hadoop.pcap.packet.HttpPacket;
import net.ripe.hadoop.pcap.packet.Packet;

public class HttpPcapReader extends PcapReader{
	public static final Log LOG = LogFactory.getLog(HttpPcapReader.class);

	public static final int HTTP_PORT = 80;
	public static final String HEADER_PREFIX = "header_";

	private HttpParams params = new BasicHttpParams();
	private HttpRequestFactory reqFactory = new DefaultHttpRequestFactory();
	private HttpResponseFactory respFactory = new DefaultHttpResponseFactory();

	public HttpPcapReader(DataInputStream is) throws IOException {
		super(is);
	}

	@Override
	protected Packet createPacket() {
		return new HttpPacket();
	}

	@Override
	protected boolean isReassemble() {
		return true;
	}

	@Override
	protected boolean isPush() {
		return false;
	}

	@Override
	protected void processPacketPayload(Packet packet, final byte[] payload) {
		HttpPacket httpPacket = (HttpPacket)packet;
		Integer srcPort = (Integer)packet.get(Packet.SRC_PORT);
		Integer dstPort = (Integer)packet.get(Packet.DST_PORT);
		if ((HTTP_PORT == srcPort || HTTP_PORT == dstPort) &&
		    packet.containsKey(Packet.REASSEMBLED_FRAGMENTS) &&
		    PROTOCOL_TCP.equals(packet.get(Packet.PROTOCOL))) {
	        final SessionInputBuffer inBuf = new AbstractSessionInputBuffer() {
	        	{
					init(new ByteArrayInputStream(payload), 1024, params);
				}

				@Override
				public boolean isDataAvailable(int timeout) throws IOException {
					return true;
				}
            };
            final SessionOutputBuffer outBuf = new AbstractSessionOutputBuffer() {};

            if (HTTP_PORT == srcPort) {
		        HttpMessageParser<HttpResponse> parser = new DefaultHttpResponseParser(inBuf, null, respFactory, params);

		        HttpClientConnection conn = new DefaultClientConnection() {
		        	{
		        		init(inBuf, outBuf, params);
		        	}

					@Override
					protected void assertNotOpen() {}

					@Override
					protected void assertOpen() {}
		        };
	
		        try {
		        	HttpResponse response = parser.parse();
		        	conn.receiveResponseEntity(response);
		        	propagateHeaders(httpPacket, response.getAllHeaders());
				} catch (IOException e) {
					LOG.error("IOException when decoding HTTP response", e);
				} catch (HttpException e) {
					LOG.error("HttpException when decoding HTTP response", e);
				}
            } else if (HTTP_PORT == dstPort) {
		        HttpMessageParser<HttpRequest> parser = new DefaultHttpRequestParser(inBuf, null, reqFactory, params);
		        try {
		        	HttpRequest request = parser.parse();
		        	propagateHeaders(httpPacket, request.getAllHeaders());
				} catch (IOException e) {
					LOG.error("IOException when decoding HTTP request", e);
				} catch (HttpException e) {
					LOG.error("HttpException when decoding HTTP request", e);
				}
            }
		}
	}

	private void propagateHeaders(HttpPacket packet, Header[] headers) {
		LinkedList<String> headerKeys = new LinkedList<String>();
		for (Header header : headers) {
			String headerKey = HEADER_PREFIX + header.getName().toLowerCase();
			packet.put(headerKey, header.getValue());
		}
		packet.put(HttpPacket.HTTP_HEADERS, Joiner.on(',').join(headerKeys));
	}
}