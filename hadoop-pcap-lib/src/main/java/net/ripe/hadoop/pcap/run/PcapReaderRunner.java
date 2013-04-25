package net.ripe.hadoop.pcap.run;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.zip.GZIPInputStream;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

public class PcapReaderRunner {
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if(args.length != 2){
            System.err.println("Usage: net.ripe.hadoop.pcap.run.PcapReaderRunner net.ripe.hadoop.pcap.PcapReader|net.ripe.hadoop.pcap.DnsPcapReader /path/to/pcap_file");
            return;
        }

		try {
			new PcapReaderRunner().run(args[0], args[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void run(String pcapReaderClass, String path) throws IOException {
		InputStream is = null;
		try {
			long packets = 0;
			System.out.println("=== START ===");

			is = new FileInputStream(path);
			if (path.endsWith(".gz") || path.endsWith(".gzip"))
				is = new GZIPInputStream(is);

			PcapReader reader = initPcapReader(pcapReaderClass, new DataInputStream(is));
	
			for (Packet packet : reader) {
				System.out.println("--- packet ---");
				System.out.println(packet.toString());
				packets++;
			}
			System.out.println("=== STOP ===");
			System.out.println("Packets: " + packets);
		} finally {
			if (is != null)
				is.close();
		}
	}

	private PcapReader initPcapReader(String className, DataInputStream is) {
		try {
			@SuppressWarnings("unchecked")
			Class<? extends PcapReader> pcapReaderClass = (Class<? extends PcapReader>)Class.forName(className);
			Constructor<? extends PcapReader> pcapReaderConstructor = pcapReaderClass.getConstructor(DataInputStream.class);
			return pcapReaderConstructor.newInstance(is);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}