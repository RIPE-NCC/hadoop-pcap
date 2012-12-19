package net.ripe.hadoop.pcap.packet;

public class DnsPacket extends Packet {
	private static final long serialVersionUID = -6989112201605879976L;

	public static final String QUERYID = "dns_queryid";
	public static final String FLAGS = "dns_flags";
	public static final String QR = "dns_qr";
	public static final String OPCODE = "dns_opcode";
	public static final String RCODE = "dns_rcode";
	public static final String QUESTION = "dns_question";
	public static final String QNAME = "dns_qname";
	public static final String QTYPE = "dns_qtype";
	public static final String ANSWER = "dns_answer";
	public static final String AUTHORITY = "dns_authority";
	public static final String ADDITIONAL = "dns_additional";
}
