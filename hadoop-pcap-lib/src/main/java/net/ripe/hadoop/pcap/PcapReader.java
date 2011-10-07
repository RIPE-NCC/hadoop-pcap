package net.ripe.hadoop.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.ripe.hadoop.pcap.packet.Packet;

public class PcapReader implements Iterable<Packet> {
	public static final Log LOG = LogFactory.getLog(PcapReader.class);

	public static final long MAGIC_NUMBER = 0xA1B2C3D4;
	public static final int HEADER_SIZE = 24;
	public static final int PACKET_HEADER_SIZE = 16;
	public static final int TIMESTAMP_OFFSET = 0;
	public static final int CAP_LEN_OFFSET = 8;
	public static final int ETHERNET_HEADER_SIZE = 14;
	public static final int ETHERNET_TYPE_OFFSET = 12;
	public static final int ETHERNET_TYPE_IP = 0x800;
	public static final int IP_HEADER_SIZE = 14;
	public static final int IP_TTL_OFFSET = 22;
	public static final int IP_PROTOCOL_OFFSET = 23;
	public static final int IP_SRC_OFFSET = 26;
	public static final int IP_DST_OFFSET = 30;
	public static final int UDP_HEADER_SIZE = 8;
	public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
	public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
	public static final int TCP_HEADER_DATA_OFFSET = 12;
	public static final String PROTOCOL_ICMP = "ICMP";
	public static final String PROTOCOL_TCP = "TCP";
	public static final String PROTOCOL_UDP = "UDP";

	private final InputStream is;
	private Iterator<Packet> iterator;

	public PcapReader(InputStream is) throws IOException {
		this.is = is;
		iterator = new PacketIterator();

		byte[] pcapHeader = new byte[HEADER_SIZE];
		if (!readBytes(pcapHeader))
			throw new IOException("Couldn't read PCAP header");

		if (!validateMagicNumber(pcapHeader))
			throw new IOException("Not a PCAP file (Couldn't find magic number)");
	}

	// Only use this constructor for testcases
	protected PcapReader() {
		this.is = null;
	}

	private Packet nextPacket() {
		byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (readBytes(pcapPacketHeader)) {
			Packet packet = createPacket();

			long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET);
			packet.put(Packet.TIMESTAMP, packetTimestamp);

			long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET);
			byte[] packetData = new byte[(int)packetSize];
			if (readBytes(packetData)) {
				if (isInternetProtocolPacket(packetData)) {
					buildInternetProtocolPacket(packet, packetData);

					final String protocol = (String)packet.get(Packet.PROTOCOL);
					if (PROTOCOL_UDP == protocol || 
					    PROTOCOL_TCP == protocol) {

						byte[] packetPayload = buildTcpAndUdpPacket(packet, packetData);
						processPacketPayload(packet, packetPayload);
					}
				}
			}

			return packet;
		}
		return null;
	}

	protected Packet createPacket() {
		return new Packet();
	}

	protected void processPacketPayload(Packet packet, byte[] payload) {}

	protected boolean validateMagicNumber(byte[] pcapHeader) {
		return PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER;
	}

	private boolean isInternetProtocolPacket(byte[] packet) {
		int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
		return etherType == ETHERNET_TYPE_IP;
	}

	private int getInternetProtocolHeaderLength(byte[] packet) {
		return (packet[IP_HEADER_SIZE] & 0xF) * 4;
	}

	private int getTcpHeaderLength(byte[] packet) {
		int dataOffset = ETHERNET_HEADER_SIZE + getInternetProtocolHeaderLength(packet) + TCP_HEADER_DATA_OFFSET;
		return ((packet[dataOffset] >> 4) & 0xF) * 4;
	}

	private void buildInternetProtocolPacket(Packet packet, byte[] packetData) {
		int ttl = packetData[IP_TTL_OFFSET] & 0xFF;
		packet.put(Packet.TTL, ttl);

		int protocol = packetData[IP_PROTOCOL_OFFSET];
		packet.put(Packet.PROTOCOL, PcapReaderUtil.convertProtocolIdentifier(protocol));

		String src = PcapReaderUtil.convertAddress(packetData, IP_SRC_OFFSET);
		packet.put(Packet.SRC, src);

		String dst = PcapReaderUtil.convertAddress(packetData, IP_DST_OFFSET);
		packet.put(Packet.DST, dst);
	}

	private byte[] buildTcpAndUdpPacket(Packet packet, byte[] packetData) {
		int srcPortOffset = ETHERNET_HEADER_SIZE + getInternetProtocolHeaderLength(packetData) + PROTOCOL_HEADER_SRC_PORT_OFFSET;
		packet.put(Packet.SRC_PORT, PcapReaderUtil.convertShort(packetData, srcPortOffset));

		int dstPortOffset = ETHERNET_HEADER_SIZE + getInternetProtocolHeaderLength(packetData) + PROTOCOL_HEADER_DST_PORT_OFFSET;
		packet.put(Packet.DST_PORT, PcapReaderUtil.convertShort(packetData, dstPortOffset));

		int headerSize;
		final String protocol = (String)packet.get(Packet.PROTOCOL);
		if (PROTOCOL_UDP.equals(protocol))
			headerSize = UDP_HEADER_SIZE;
		else if (PROTOCOL_TCP.equals(protocol))
			headerSize = getTcpHeaderLength(packetData);
		else
			return null;

		int payloadDataStart = ETHERNET_HEADER_SIZE + getInternetProtocolHeaderLength(packetData) + headerSize;
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
			if (is.read(buf) != -1)
				return true;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
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