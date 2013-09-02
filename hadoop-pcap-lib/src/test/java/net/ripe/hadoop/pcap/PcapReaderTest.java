package net.ripe.hadoop.pcap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Iterables;

public class PcapReaderTest {
	PcapReader reader;

	@Before
	public void init() throws IOException {
		reader = new PcapReader(PcapReader.LinkType.NULL);
	}

	@Test
	public void emptyFile() throws IOException {
		new PcapReader(new DataInputStream(new ByteArrayInputStream(new byte[0])));
	}

	@Test
	public void readPayload() {
		byte[] stringBytes = new String("foo bar").getBytes();
		byte[] payload = reader.readPayload(stringBytes, 4, stringBytes.length-4);
		assertEquals("bar", new String(payload));
	}

	@Test
	public void readPayloadBrokenOffset() {
		byte[] payload = reader.readPayload(new byte[1], 2, 1);
		assertTrue(0 == payload.length);
	}

	@Test
	public void getLinkTypeNULL() {
		assertEquals(PcapReader.LinkType.NULL, reader.getLinkType(0));
	}

	@Test
	public void getLinkTypeEN10MB() {
		assertEquals(PcapReader.LinkType.EN10MB, reader.getLinkType(1));
	}

	@Test
	public void getLinkTypeRAW() {
		assertEquals(PcapReader.LinkType.RAW, reader.getLinkType(101));
	}

	@Test
	public void getLinkTypeLOOP() {
		assertEquals(PcapReader.LinkType.LOOP, reader.getLinkType(108));
	}

	@Test
	public void getLinkTypeSLL() {
		assertEquals(PcapReader.LinkType.LINUX_SLL, reader.getLinkType(113));
	}

	@Test
	public void findIPStartNULL() {
		PcapReader xreader = new PcapReader(PcapReader.LinkType.NULL);
		assertEquals(4, xreader.findIPStart(null));
	}

	@Test
	public void findIPStartEN10MB_8021Q() {
		byte[] packet = new byte[20];
		PcapReader xreader = new PcapReader(PcapReader.LinkType.EN10MB);

		byte[] ethernetType8021Q = PcapReaderUtil.convertShort(PcapReader.ETHERNET_TYPE_8021Q);
		packet[12] = ethernetType8021Q[0];
		packet[13] = ethernetType8021Q[1];

		byte[] ethernetTypeIp = PcapReaderUtil.convertShort(PcapReader.ETHERNET_TYPE_IP);
		packet[16] = ethernetTypeIp[0];
		packet[17] = ethernetTypeIp[1];

		assertEquals(18, xreader.findIPStart(packet));
	}

	@Test
	public void findIPStartSLL() {
		byte[] packet = new byte[20];
		PcapReader xreader = new PcapReader(PcapReader.LinkType.LINUX_SLL);

		byte[] sllAddressSourceLength = PcapReaderUtil.convertShort(6);
		packet[4] = sllAddressSourceLength[0];
		packet[5] = sllAddressSourceLength[1];

		byte[] ethernetTypeIp = PcapReaderUtil.convertShort(PcapReader.ETHERNET_TYPE_IP);
		packet[16] = ethernetTypeIp[0];
		packet[17] = ethernetTypeIp[1];

		assertEquals(16, xreader.findIPStart(packet));
	}

	@Test
	public void findIPStartEN10MB() {
		byte[] packet = new byte[20];
		PcapReader xreader = new PcapReader(PcapReader.LinkType.EN10MB);

		byte[] ethernetType = PcapReaderUtil.convertShort(PcapReader.ETHERNET_TYPE_IP);
		packet[12] = ethernetType[0];
		packet[13] = ethernetType[1];

		assertEquals(14, xreader.findIPStart(packet));
	}

	@Test
	public void findIPStartEN10MBUnknownType() {
		byte[] packet = new byte[20];
		PcapReader xreader = new PcapReader(PcapReader.LinkType.EN10MB);

		packet[12] = -1;
		packet[13] = -1;

		assertEquals(-1, xreader.findIPStart(packet));
	}

	@Test
	public void findIPStartRAW() {
		PcapReader xreader = new PcapReader(PcapReader.LinkType.RAW);
		assertEquals(0, xreader.findIPStart(null));
	}

	@Test
	public void findIPStartLOOP() {
		PcapReader xreader = new PcapReader(PcapReader.LinkType.LOOP);
		assertEquals(4, xreader.findIPStart(null));
	}

	@Test
	public void assembled() throws IOException {
		for (String file : new String[] { "src/test/resources/tcp-stream-v4.pcap", "src/test/resources/tcp-stream-v6.pcap" }) {
			PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(file))) {
				@Override
				protected void processPacketPayload(Packet packet, byte[] payload) {
					Integer fragments = (Integer)packet.get(Packet.REASSEMBLED_FRAGMENTS);
					if (fragments != null) {
						assertTrue(2 == fragments);
						assertEquals("part1\npart2\n", new String(payload));
					}
				}
	
				@Override
				protected boolean isReassemble() {
					return true;
				}
	
				@Override
				protected boolean isPush() {
					return false;
				}
			};
			assertEquals(10, Iterables.size(reader));
		}
	}

	@Test
	public void assembledWithPush() throws IOException {
		for (String file : new String[] { "src/test/resources/tcp-stream-v4.pcap", "src/test/resources/tcp-stream-v6.pcap" }) {
			PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(file))) {
				public int counter = 1;
	
				@Override
				protected void processPacketPayload(Packet packet, byte[] payload) {
					Integer fragments = (Integer)packet.get(Packet.REASSEMBLED_FRAGMENTS);
					if (fragments != null) {
						assertTrue(1 == fragments);
						switch (counter) {
							case 1:
								assertEquals("part1\n", new String(payload));
								break;
							case 2:
								assertEquals("part2\n", new String(payload));
								break;
						}
						counter++;
					}
				}
	
				@Override
				protected boolean isReassemble() {
					return true;
				}
	
				@Override
				protected boolean isPush() {
					return true;
				}
			};
			assertEquals(10, Iterables.size(reader));
		}
	}
}
