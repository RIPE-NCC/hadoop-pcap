package net.ripe.hadoop.pcap;

import static org.junit.Assert.*;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

import net.ripe.hadoop.pcap.packet.Packet;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Iterators;

public class HttpPcapReaderTest {
	private HttpPcapReader reader;

	@Before
	public void init() throws IOException {
		reader = new HttpPcapReader(new DataInputStream(new FileInputStream("src/test/resources/http.pcap")));
	}

	@Test
	public void test() {
		Packet[] packets = Iterators.toArray(reader.iterator(), Packet.class);
		assertEquals(10, packets.length);

		// Request
		assertEquals("curl/7.39.0", packets[7].get("header_user-agent"));
		assertEquals("www.google.com", packets[7].get("header_host"));
		assertEquals("*/*", packets[7].get("header_accept"));
		assertEquals("header_user-agent,header_host,header_accept", packets[7].get("http_headers"));

		// Response
		assertEquals("private", packets[8].get("header_cache-control"));
		assertEquals("text/html; charset=UTF-8", packets[8].get("header_content-type"));
		assertEquals("http://www.google.com.au/?gfe_rd=cr&ei=gzYqVYPJLqWN8QedpoHYDA", packets[8].get("header_location"));
		assertEquals("262", packets[8].get("header_content-length"));
		assertEquals("Sun, 12 Apr 2015 09:10:27 GMT", packets[8].get("header_date"));
		assertEquals("GFE/2.0", packets[8].get("header_server"));
		assertEquals("80:quic,p=0.5", packets[8].get("header_alternate-protocol"));
		assertEquals("header_cache-control,header_content-type,header_location,header_content-length,header_date,header_server,header_alternate-protocol", packets[8].get("http_headers"));
	}
}