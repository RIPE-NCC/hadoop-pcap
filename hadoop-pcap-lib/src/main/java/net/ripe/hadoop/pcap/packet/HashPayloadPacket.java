package net.ripe.hadoop.pcap.packet;

public class HashPayloadPacket extends Packet {
	private static final long serialVersionUID = -6975384346515055768L;

	public static final String PAYLOAD_SHA1_HASH = "payload_sha1_hash";
	public static final String PAYLOAD_SHA256_HASH = "payload_sha256_hash";
	public static final String PAYLOAD_SHA512_HASH = "payload_sha512_hash";
	public static final String PAYLOAD_MD5_HASH = "payload_md5_hash";
}