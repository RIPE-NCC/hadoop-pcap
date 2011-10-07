package net.ripe.hadoop.pcap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import net.ripe.hadoop.pcap.PcapReader;

import org.junit.Before;
import org.junit.Test;

public class PcapReaderTest {
	PcapReader reader;

	@Before
	public void init() throws IOException {
		reader = new PcapReader();
	}

	@Test
	public void readPayload() {
		byte[] payload = reader.readPayload(new String("foo bar").getBytes(), 4);
		assertEquals("bar", new String(payload));
	}

	@Test
	public void readPayloadBrokenOffset() {
		byte[] payload = reader.readPayload(new byte[1], 2);
		assertTrue(0 == payload.length);
	}
}