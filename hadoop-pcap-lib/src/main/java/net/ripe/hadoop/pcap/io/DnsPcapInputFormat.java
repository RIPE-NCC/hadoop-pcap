package net.ripe.hadoop.pcap.io;

import java.io.IOException;
import java.io.InputStream;

import net.ripe.hadoop.pcap.DnsPcapReader;
import net.ripe.hadoop.pcap.PcapReader;

public class DnsPcapInputFormat extends PcapInputFormat {
	@Override
	protected PcapReader initPcapReader(InputStream is) throws IOException {
		return new DnsPcapReader(is);
	}
}