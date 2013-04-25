package net.ripe.hadoop.pcap;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.math.BigInteger;

public class PcapReaderUtil {
	private static Map<Integer, String> protocols;

	static {
		protocols = new HashMap<Integer, String>();
		protocols.put(1, PcapReader.PROTOCOL_ICMP);
		protocols.put(6, PcapReader.PROTOCOL_TCP);
		protocols.put(17, PcapReader.PROTOCOL_UDP);
	}

	public static long convertInt(byte[] data) {
		return convertInt(data, false);
	}
	
	public static long convertInt(byte[] data, boolean reversed) {
		if (!reversed)
		{
			return ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16)
					| ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
		}
		else
		{
			return ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16)
					| ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
		}
	}

	public static long convertInt(byte[] data, int offset, boolean reversed) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertInt(target, reversed);
	}
	
	public static long convertInt(byte[] data, int offset) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertInt(target, false);
	}

	public static int convertShort(byte[] data) {
		return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
	}

	public static byte[] convertShort(int data) {
		byte[] result = new byte[2];
		result[0] = (byte)(data >> 8);
		result[1] = (byte)(data);
		return result;
	}

	public static int convertShort(byte[] data, int offset) {
		byte[] target = new byte[2];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertShort(target);
	}

	//A java workaround for header fields like seq/ack which are ulongs --M
	public static long convertUnsignedInt(byte[] data,int offset) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);

		BigInteger placeholder = new BigInteger(1,target);
		return placeholder.longValue();
	}

	public static String convertProtocolIdentifier(int identifier) {
		return protocols.get(identifier);
	}

	public static String convertAddress(byte[] data, int offset, int size) {
		byte[] addr = new byte[size];
		System.arraycopy(data, offset, addr, 0, addr.length);
		try {
			return InetAddress.getByAddress(addr).getHostAddress();
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return null;
		}
	}
}
