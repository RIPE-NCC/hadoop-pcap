package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.IOException;

import com.google.common.hash.Hashing;

import net.ripe.hadoop.pcap.packet.HashPayloadPacket;
import net.ripe.hadoop.pcap.packet.Packet;

public class HashPayloadPcapReader extends PcapReader {
	public HashPayloadPcapReader(DataInputStream is) throws IOException {
		super(is);
	}

	@Override
	protected Packet createPacket() {
		return new HashPayloadPacket();
	}

	@Override
	protected boolean isReassemble() {
		return true;
	}

	@Override
	protected boolean isPush() {
		return false;
	}

	@Override
	protected void processPacketPayload(Packet packet, byte[] payload) {
		if (payload.length > 0) {
			packet.put(HashPayloadPacket.PAYLOAD_SHA1_HASH, Hashing.sha1().hashBytes(payload).toString());
			packet.put(HashPayloadPacket.PAYLOAD_SHA256_HASH, Hashing.sha256().hashBytes(payload).toString());
			packet.put(HashPayloadPacket.PAYLOAD_SHA512_HASH, Hashing.sha512().hashBytes(payload).toString());
			packet.put(HashPayloadPacket.PAYLOAD_MD5_HASH, Hashing.md5().hashBytes(payload).toString());
		}
	}
}