package net.ripe.hadoop.pcap;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;

import net.ripe.hadoop.pcap.DnsPcapReader;

import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.OPTRecord;

public class DnsPcapReaderTest {
	private DnsPcapReader pcapReader;

	@Before
	public void init() throws IOException {
		pcapReader = new TestableDnsPcapReader();
	}

	@Test
	public void normalizeOPTRecord() throws IOException {
		OPTRecord record = new OPTRecord(4096, 0, 0, 32768);
		assertEquals(". 32768 CLASS4096 OPT ; payload 4096, xrcode 0, version 0, flags 32768",
		             pcapReader.normalizeRecordString(record.toString()));
	}

	private class TestableDnsPcapReader extends DnsPcapReader {
		public TestableDnsPcapReader() throws IOException {
			super(new InputStream() {
				@Override
				public int read() throws IOException {
					return -1; // Return dummy data for test
				}
			});
		}

		@Override
		protected boolean readBytes(byte[] buf) {
			return true;
		}

		@Override
		protected boolean validateMagicNumber(byte[] pcapHeader) {
			return true;
		}
	}
}