package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;

import net.ripe.hadoop.pcap.DnsPcapReader;
import net.ripe.hadoop.pcap.PcapReader;

public class DnsPcapInputFormat extends PcapInputFormat {
	@Override
	protected PcapReader initPcapReader(DataInputStream is) throws IOException {
		return new DnsPcapReader(is);
	}
}