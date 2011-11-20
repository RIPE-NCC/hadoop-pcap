package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.ripe.hadoop.pcap.packet.Packet;

public class PcapReader implements Iterable<Packet> {
	public static final Log LOG = LogFactory.getLog(PcapReader.class);

	public static final long MAGIC_NUMBER = 0xA1B2C3D4;
	public static final int HEADER_SIZE = 24;
	public static final int PCAP_HEADER_LINKTYPE_OFFSET = 20;
	public static final int PACKET_HEADER_SIZE = 16;
	public static final int TIMESTAMP_OFFSET = 0;
	public static final int CAP_LEN_OFFSET = 8;
	public static final int ETHERNET_HEADER_SIZE = 14;
	public static final int ETHERNET_TYPE_OFFSET = 12;
	public static final int ETHERNET_TYPE_IP = 0x800;
	public static final int ETHERNET_TYPE_8021Q = 0x8100;
	public static final int IP_VHL_OFFSET = 0;	// relative to start of IP header
	public static final int IP_TTL_OFFSET = 8;	// relative to start of IP header
	public static final int IP_PROTOCOL_OFFSET = 9;	// relative to start of IP header
	public static final int IP_SRC_OFFSET = 12;	// relative to start of IP header
	public static final int IP_DST_OFFSET = 16;	// relative to start of IP header
	public static final int UDP_HEADER_SIZE = 8;
	public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
	public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
	public static final int TCP_HEADER_DATA_OFFSET = 12;
	public static final String PROTOCOL_ICMP = "ICMP";
	public static final String PROTOCOL_TCP = "TCP";
	public static final String PROTOCOL_UDP = "UDP";

	private final DataInputStream is;
	private Iterator<Packet> iterator;
	private LinkType linkType;

	public PcapReader(DataInputStream is) throws IOException {
		this.is = is;
		iterator = new PacketIterator();

		byte[] pcapHeader = new byte[HEADER_SIZE];
		if (!readBytes(pcapHeader))
			throw new IOException("Couldn't read PCAP header");

		if (!validateMagicNumber(pcapHeader))
			throw new IOException("Not a PCAP file (Couldn't find magic number)");

		long linkTypeVal = PcapReaderUtil.convertInt(pcapHeader, PCAP_HEADER_LINKTYPE_OFFSET);
		if ((linkType = getLinkType(linkTypeVal)) == null)
			throw new IOException("Unsupported link type: " + linkTypeVal);
	}

	// Only use this constructor for testcases
	protected PcapReader() {
		this.is = null;
	}

	private Packet nextPacket() {
		byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (!readBytes(pcapPacketHeader))
			return null;

		Packet packet = createPacket();

		long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET);
		packet.put(Packet.TIMESTAMP, packetTimestamp);

		long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET);
		byte[] packetData = new byte[(int)packetSize];
		if (!readBytes(packetData))
			return packet;

		int ipStart = findIPStart(linkType, packetData);
		if (ipStart == -1)
			return packet;

		if (getInternetProtocolHeaderVersion(packetData, ipStart) == 4) {
			buildInternetProtocolV4Packet(packet, packetData, ipStart);
	
			String protocol = (String)packet.get(Packet.PROTOCOL);
			if (PROTOCOL_UDP == protocol || 
			    PROTOCOL_TCP == protocol) {
	
				byte[] packetPayload = buildTcpAndUdpPacket(packet, packetData, ipStart);
				processPacketPayload(packet, packetPayload);
			}
		}

		return packet;
	}

	protected Packet createPacket() {
		return new Packet();
	}

	protected void processPacketPayload(Packet packet, byte[] payload) {}

	protected boolean validateMagicNumber(byte[] pcapHeader) {
		return PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER;
	}

	protected enum LinkType {
		NULL, EN10MB, RAW, LOOP
	}

	protected LinkType getLinkType(long linkTypeVal) {
		switch ((int)linkTypeVal) {
			case 0:
				return LinkType.NULL;
			case 1:
				return LinkType.EN10MB;
			case 101:
				return LinkType.RAW;
			case 108:
				return LinkType.LOOP;
		}
		return null;
	}

	protected int findIPStart(LinkType linkType, byte[] packet) {
		switch (linkType) {
			case NULL:
				return 0;
			case EN10MB:
				int start = ETHERNET_HEADER_SIZE;
				int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
				if (etherType == ETHERNET_TYPE_8021Q) {
					etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET + 4);
					start += 4;
				}
				if (etherType == ETHERNET_TYPE_IP)
					return start;
				break;
			case RAW:
				return 0;
			case LOOP:
				return 4;
		}
		return -1;
	}

	private int getInternetProtocolHeaderLength(byte[] packet, int ipStart) {
		return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
	}

	private int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
		return (packet[ipStart + IP_VHL_OFFSET] >> 4) & 0xF;
	}

	private int getTcpHeaderLength(byte[] packet, int tcpStart) {
		int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
		return ((packet[dataOffset] >> 4) & 0xF) * 4;
	}

	private void buildInternetProtocolV4Packet(Packet packet, byte[] packetData, int ipStart) {
		int ttl = packetData[ipStart + IP_TTL_OFFSET] & 0xFF;
		packet.put(Packet.TTL, ttl);

		int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
		packet.put(Packet.PROTOCOL, PcapReaderUtil.convertProtocolIdentifier(protocol));

		String src = PcapReaderUtil.convertAddress(packetData, ipStart + IP_SRC_OFFSET);
		packet.put(Packet.SRC, src);

		String dst = PcapReaderUtil.convertAddress(packetData, ipStart + IP_DST_OFFSET);
		packet.put(Packet.DST, dst);
	}

	/*
	 * packetData is the entire layer 2 packet read from pcap
	 * ipStart is the start of the IP packet in packetData
	 */
	private byte[] buildTcpAndUdpPacket(Packet packet, byte[] packetData, int ipStart) {
		int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipStart);

		packet.put(Packet.SRC_PORT, PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + PROTOCOL_HEADER_SRC_PORT_OFFSET));

		packet.put(Packet.DST_PORT, PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + PROTOCOL_HEADER_DST_PORT_OFFSET));

		int headerSize;
		final String protocol = (String)packet.get(Packet.PROTOCOL);
		if (PROTOCOL_UDP.equals(protocol))
			headerSize = UDP_HEADER_SIZE;
		else if (PROTOCOL_TCP.equals(protocol))
			headerSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);
		else
			return null;

		int payloadDataStart = ipStart + ipHeaderLen + headerSize;
		byte[] data = readPayload(packetData, payloadDataStart);
		packet.put(Packet.LEN, data.length);
		return data;
	}

	/**
	 * Reads the packet payload and returns it as byte[].
	 * If the payload could not be read an empty byte[] is returned.
	 * @param packetData
	 * @param payloadDataStart
	 * @return payload as byte[]
	 */
	protected byte[] readPayload(byte[] packetData, int payloadDataStart) {
		if (payloadDataStart > packetData.length) {
			LOG.warn("Payload start is larger than packet data. Returning empty payload.");
			return new byte[0];
		}
		byte[] data = new byte[packetData.length - payloadDataStart];
		System.arraycopy(packetData, payloadDataStart, data, 0, data.length);
		return data;
	}

	protected boolean readBytes(byte[] buf) {
		try {
			is.readFully(buf);
			return true;
		} catch (EOFException e) {
			// Reached the end of the stream
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public Iterator<Packet> iterator() {
		return iterator;
	}

	private class PacketIterator implements Iterator<Packet> {
		private Packet next;

		private void fetchNext() {
			if (next == null)
				next = nextPacket();
		}

		@Override
		public boolean hasNext() {
			fetchNext();
			if (next != null)
				return true;
			return false;
		}

		@Override
		public Packet next() {
			fetchNext();
			try {
				return next;
			} finally {
				next = null;
			}
		}

		@Override
		public void remove() {
			// Not supported
		}
	}
}
