package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.ripe.hadoop.pcap.packet.DnsPacket;
import net.ripe.hadoop.pcap.packet.Packet;

import org.xbill.DNS.*;

public class DnsPcapReader extends PcapReader {
	public static final int DNS_PORT = 53;

	public DnsPcapReader(DataInputStream is) throws IOException {
		super(is);
	}

	@Override
	protected Packet createPacket() {
		return new DnsPacket();
	}

	@Override
	protected boolean isReassembleDatagram() {
		return true;
	}

	@Override
	protected boolean isReassembleTcp() {
		return true;
	}

	@Override
	protected boolean isPush() {
		return false;
	}

	@Override
	protected void processPacketPayload(Packet packet, byte[] payload) {
		String protocol = (String)packet.get(Packet.PROTOCOL);

		if (!PcapReader.PROTOCOL_UDP.equals(protocol) && !PcapReader.PROTOCOL_TCP.equals(protocol))
			return;

		DnsPacket dnsPacket = (DnsPacket)packet;

		if (DNS_PORT == (Integer)packet.get(Packet.SRC_PORT) || DNS_PORT == (Integer)packet.get(Packet.DST_PORT)) {
			if (PROTOCOL_TCP.equals(protocol) &&
			    payload.length > 2) // TODO Support DNS responses with multiple messages (as used for XFRs)
				payload = Arrays.copyOfRange(payload, 2, payload.length); // First two bytes denote the size of the DNS message, ignore them
			try {
				Message msg = new Message(payload);
				Header header = msg.getHeader();
				dnsPacket.put(DnsPacket.QUERYID, header.getID());
				dnsPacket.put(DnsPacket.FLAGS, header.printFlags());
                dnsPacket.put(DnsPacket.AA, header.getFlag(Flags.AA));
                dnsPacket.put(DnsPacket.TC, header.getFlag(Flags.TC));
				dnsPacket.put(DnsPacket.QR, header.getFlag(Flags.QR));
                dnsPacket.put(DnsPacket.RD, header.getFlag(Flags.RD));
                dnsPacket.put(DnsPacket.RA, header.getFlag(Flags.RA));
				dnsPacket.put(DnsPacket.OPCODE, Opcode.string(header.getOpcode()));
				dnsPacket.put(DnsPacket.RCODE, Rcode.string(header.getRcode()));
				dnsPacket.put(DnsPacket.QUESTION, convertRecordToString(msg.getQuestion()));
				dnsPacket.put(DnsPacket.QNAME, convertRecordOwnerToString(msg.getQuestion()));
				dnsPacket.put(DnsPacket.QTYPE, Type.string(msg.getQuestion().getType()));
                dnsPacket.put(DnsPacket.QCLASS, DClass.string(msg.getQuestion().getDClass()));
				dnsPacket.put(DnsPacket.ANSWER, convertRecordsToStrings(msg.getSectionArray(Section.ANSWER)));
				dnsPacket.put(DnsPacket.AUTHORITY, convertRecordsToStrings(msg.getSectionArray(Section.AUTHORITY)));
				dnsPacket.put(DnsPacket.ADDITIONAL, convertRecordsToStrings(msg.getSectionArray(Section.ADDITIONAL)));
			} catch (Exception e) {
				// If we cannot decode a DNS packet we ignore it
			}
		}
	}

	private String convertRecordToString(Record record) {
		if (record == null)
			return null;

		String recordString = record.toString();
		recordString = normalizeRecordString(recordString);
		return recordString;
	}

	private String convertRecordOwnerToString(Record record) {
		if (record == null)
			return null;
		String ownerString = record.getName().toString();
		ownerString = ownerString.toLowerCase();
		return ownerString;
	}

	private List<String> convertRecordsToStrings(Record[] records) {
		if (records == null)
			return null;

		ArrayList<String> retVal = new ArrayList<String>(records.length);
		for (Record record : records)
			retVal.add(convertRecordToString(record));
		return retVal;
	}

	protected String normalizeRecordString(String recordString) {
		if (recordString == null)
			return null;

		// Reduce everything that is more than one whitespace to a single whitespace
		recordString = recordString.replaceAll("\\s{2,}", " ");
		// Replace tabs with a single whitespace
		recordString = recordString.replaceAll("\\t{1,}", " ");
		return recordString;
	}
}
