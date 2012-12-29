package net.ripe.hadoop.pcap.packet;

public class HttpPacket extends Packet {
	private static final long serialVersionUID = -6989112201605879976L;

 	public static final String GET = "http_get";
	public static final String HOST = "http_host";
	public static final String USER_AGENT = "http_user_agent";
	public static final String ACCEPT = "http_accept";
	public static final String ACCEPT_LANGUAGE = "http_accept_language";
	public static final String ACCEPT_ENCODING = "http_accept_encoding";
	public static final String ACCEPT_CHARSET = "http_accept_charset";
	public static final String KEEP_ALIVE = "http_keep_alive";
	public static final String CONNECTION = "http_connection";
	public static final String REFERER = "http_referer";
}