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
	public static final int TIMESTAMP_MICROS_OFFSET = 4;
	public static final int CAP_LEN_OFFSET = 8;
	public static final int ETHERNET_HEADER_SIZE = 14;
	public static final int ETHERNET_TYPE_OFFSET = 12;
	public static final int ETHERNET_TYPE_IP = 0x800;
	public static final int ETHERNET_TYPE_8021Q = 0x8100;
	public static final int SLL_HEADER_BASE_SIZE = 10; // SLL stands for Linux cooked-mode capture
	public static final int SLL_ADDRESS_LENGTH_OFFSET = 4; // relative to SLL header
	public static final int IP_VHL_OFFSET = 0;	// relative to start of IP header
	public static final int IP_TTL_OFFSET = 8;	// relative to start of IP header
	public static final int IP_PROTOCOL_OFFSET = 9;	// relative to start of IP header
	public static final int IP_SRC_OFFSET = 12;	// relative to start of IP header
	public static final int IP_DST_OFFSET = 16;	// relative to start of IP header
	public static final int UDP_HEADER_SIZE = 8;
	public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
	public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
        public static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
        public static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
	public static final int TCP_HEADER_DATA_OFFSET = 12;
	public static final String PROTOCOL_ICMP = "ICMP";
	public static final String PROTOCOL_TCP = "TCP";
	public static final String PROTOCOL_UDP = "UDP";

	private final DataInputStream is;
	private Iterator<Packet> iterator;
	private LinkType linkType;
	private boolean caughtEOF = false;
	
	//To read reversed-endian PCAPs; the header is the only part that switches
	private boolean reverseHeaderByteOrder = false;

	public PcapReader(DataInputStream is) throws IOException {
		this.is = is;
		iterator = new PacketIterator();

		byte[] pcapHeader = new byte[HEADER_SIZE];
		if (!readBytes(pcapHeader)) {
			//
			// This special check for EOF is because we don't want
			// PcapReader to barf on an empty file.  This is the only
			// place we check caughtEOF.
			//
			if (caughtEOF) {
				LOG.warn("Skipping empty file");
				return;
			}
			throw new IOException("Couldn't read PCAP header");
		}

		if (!validateMagicNumber(pcapHeader))
			throw new IOException("Not a PCAP file (Couldn't find magic number)");

		long linkTypeVal = PcapReaderUtil.convertInt(pcapHeader, PCAP_HEADER_LINKTYPE_OFFSET, reverseHeaderByteOrder);
		if ((linkType = getLinkType(linkTypeVal)) == null)
			throw new IOException("Unsupported link type: " + linkTypeVal);
	}

	// Only use this constructor for testcases
	protected PcapReader(LinkType lt) {
		this.is = null;
		linkType = lt;
	}

	private int getUdpChecksum(byte[] packetData, int ipStart, int ipHeaderLen) {
		/*
		 * No Checksum on this packet?
		 */
		if (packetData[ipStart + ipHeaderLen + 6] == 0 &&
		    packetData[ipStart + ipHeaderLen + 7] == 0)
			return -1;

		/*
		 * Build data[] that we can checksum.  Its a pseudo-header
		 * followed by the entire UDP packet.
		 */
		byte data[] = new byte[packetData.length - ipStart - ipHeaderLen + 12];
		int sum = 0;
		System.arraycopy(packetData, ipStart + IP_SRC_OFFSET,      data, 0, 4);
		System.arraycopy(packetData, ipStart + IP_DST_OFFSET,      data, 4, 4);
		data[8] = 0;
		data[9] = 17;	/* IPPROTO_UDP */
		System.arraycopy(packetData, ipStart + ipHeaderLen + 4,    data, 10, 2);
		System.arraycopy(packetData, ipStart + ipHeaderLen,        data, 12, packetData.length - ipStart - ipHeaderLen);
		for (int i = 0; i<data.length; i++) {
			int j = data[i];
			if (j < 0)
				j += 256;
			sum += j << (i % 2 == 0 ? 8 : 0);
		}
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		return (~sum) & 0xffff;
	}

	private int getUdpLength(byte[] packetData, int ipStart, int ipHeaderLen) {
		int udpLen = PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + 4);
		return udpLen;
	}

	private Packet nextPacket() {
		byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (!readBytes(pcapPacketHeader))
			return null;

		Packet packet = createPacket();

		long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET, reverseHeaderByteOrder);
		packet.put(Packet.TIMESTAMP, packetTimestamp);

		long packetTimestampMicros = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_MICROS_OFFSET, reverseHeaderByteOrder);
		packet.put(Packet.TIMESTAMP_MICROS, packetTimestampMicros);

		long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET, reverseHeaderByteOrder);
		byte[] packetData = new byte[(int)packetSize];
		if (!readBytes(packetData))
			return packet;

		int ipStart = findIPStart(packetData);
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
		
		if (PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER)
		{
			return true;
		}
		else if (PcapReaderUtil.convertInt(pcapHeader, true) == MAGIC_NUMBER)
		{
			reverseHeaderByteOrder = true;
			return true;
		}
		else
		{
			return false;
		}
	}

	protected enum LinkType {
		NULL, EN10MB, RAW, LOOP, LINUX_SLL
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
			case 113: 
				return LinkType.LINUX_SLL;
		}
		return null;
	}

	protected int findIPStart(byte[] packet) {
		int start = -1;
		switch (linkType) {
			case NULL:
				return 0;
			case EN10MB:
				start = ETHERNET_HEADER_SIZE;
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
			case LINUX_SLL:
			    start = SLL_HEADER_BASE_SIZE;
				int sllAddressLength = PcapReaderUtil.convertShort(packet, SLL_ADDRESS_LENGTH_OFFSET);
				start += sllAddressLength;
				return start;
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

		int tcpOrUdpHeaderSize;
		int payloadLength = 0;
		final String protocol = (String)packet.get(Packet.PROTOCOL);
		if (PROTOCOL_UDP.equals(protocol)) {
			tcpOrUdpHeaderSize = UDP_HEADER_SIZE;
			int cksum = getUdpChecksum(packetData, ipStart, ipHeaderLen);
			if (cksum >= 0)
				packet.put(Packet.UDPSUM, cksum);
			int udpLen = getUdpLength(packetData, ipStart, ipHeaderLen);
			packet.put(Packet.UDP_LENGTH, udpLen);
			payloadLength = udpLen - UDP_HEADER_SIZE; // UDP header size is 8
		} else if (PROTOCOL_TCP.equals(protocol)) {
			tcpOrUdpHeaderSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);
                        
			//Store the sequence and acknowledgement numbers --M

                        packet.put(Packet.TCP_SEQ,PcapReaderUtil.convertInt(packetData,ipStart+ ipHeaderLen + PROTOCOL_HEADER_TCP_SEQ_OFFSET));
                        packet.put(Packet.TCP_ACK,PcapReaderUtil.convertInt(packetData,ipStart + ipHeaderLen + PROTOCOL_HEADER_TCP_ACK_OFFSET));


			// Flags stretch two bytes starting at the TCP header offset
			int flags = PcapReaderUtil.convertShort(new byte[] { packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET],
			                                                     packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET + 1] })
			                                       & 0x1FF; // Filter first 7 bits. First 4 are the data offset and the other 3 reserved for future use.
			packet.put(Packet.TCP_FLAG_NS, (flags & 0x100) == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_CWR, (flags & 0x80) == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_ECE, (flags & 0x40) == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_URG, (flags & 0x20) == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_ACK, (flags & 0x10) == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_PSH, (flags & 0x8)  == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_RST, (flags & 0x4)  == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_SYN, (flags & 0x2)  == 0 ? false : true);
			packet.put(Packet.TCP_FLAG_FIN, (flags & 0x1)  == 0 ? false : true);
			payloadLength = packetData.length - (ipStart + ipHeaderLen + tcpOrUdpHeaderSize);
		} else {
			return null;
		}

		int payloadDataStart = ipStart + ipHeaderLen + tcpOrUdpHeaderSize;
		byte[] data = readPayload(packetData, payloadDataStart, payloadLength);
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
	protected byte[] readPayload(byte[] packetData, int payloadDataStart, int payloadLength) {
		if (payloadDataStart > packetData.length) {
			LOG.warn("Payload start (" + payloadDataStart + ") is larger than packet data (" + packetData.length + "). Returning empty payload.");
			return new byte[0];
		}
		if (payloadDataStart + payloadLength > packetData.length) {
			// probably a corrupted packet. 
			LOG.warn("Payload length field value (" + payloadLength + ") is larger than available packet data (" 
					+ (packetData.length - payloadDataStart) 
					+ "). Packet may be corrupted. Returning only available data.");
			payloadLength = packetData.length - payloadDataStart;
		}
		byte[] data = new byte[payloadLength];
		System.arraycopy(packetData, payloadDataStart, data, 0, payloadLength);
		return data;
	}

	protected boolean readBytes(byte[] buf) {
		try {
			is.readFully(buf);
			return true;
		} catch (EOFException e) {
			// Reached the end of the stream
			caughtEOF = true;
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
