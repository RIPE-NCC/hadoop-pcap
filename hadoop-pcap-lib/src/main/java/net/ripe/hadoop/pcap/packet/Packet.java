package net.ripe.hadoop.pcap.packet;

import java.util.HashMap;
import java.util.Map;

public class Packet extends HashMap<String, Object> {
	private static final long serialVersionUID = 8723206921174160146L;

	public static final String TIMESTAMP = "ts";
	public static final String TIMESTAMP_MICROS = "tsmicros";
	public static final String TTL = "ttl";
	public static final String PROTOCOL = "protocol";
	public static final String SRC = "src";
	public static final String DST = "dst";
	public static final String SRC_PORT = "src_port";
	public static final String DST_PORT = "dst_port";
        public static final String TCP_SEQ = "tcp_seq";
        public static final String TCP_ACK = "tcp_ack";
	public static final String LEN = "len";
	public static final String UDPSUM = "udpsum";
	public static final String UDP_LENGTH = "udp_length";
	public static final String TCP_FLAG_NS = "tcp_flag_ns";
	public static final String TCP_FLAG_CWR = "tcp_flag_cwr";
	public static final String TCP_FLAG_ECE = "tcp_flag_ece";
	public static final String TCP_FLAG_URG = "tcp_flag_urg";
	public static final String TCP_FLAG_ACK = "tcp_flag_ack";
	public static final String TCP_FLAG_PSH = "tcp_flag_psh";
	public static final String TCP_FLAG_RST = "tcp_flag_rst";
	public static final String TCP_FLAG_SYN = "tcp_flag_syn";
	public static final String TCP_FLAG_FIN = "tcp_flag_fin";

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		for (Map.Entry<String, Object> entry : entrySet()) {
			sb.append(entry.getKey());
			sb.append('=');
			sb.append(entry.getValue());
			sb.append(',');
		}
		if (sb.length() > 0)
			return sb.substring(0, sb.length() - 1);
		return null;
	}
}
