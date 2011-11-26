package net.ripe.hadoop.pcap.io.reader;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;

public class PcapRecordReader implements RecordReader<LongWritable, ObjectWritable> {
	PcapReader pcapReader;
	Iterator<Packet> pcapReaderIterator;
	Seekable baseStream;
	DataInputStream stream;
	Reporter reporter;

	long packetCount = 0;
	long start, end;

	public PcapRecordReader(PcapReader pcapReader, long start, long end, Seekable baseStream, DataInputStream stream, Reporter reporter) throws IOException {
		this.pcapReader = pcapReader;
		this.baseStream = baseStream;
		this.stream = stream;
		this.start = start;
		this.end = end;
		this.reporter = reporter;

		pcapReaderIterator = pcapReader.iterator();
	}

	@Override
	public void close() throws IOException {
		stream.close();
	}

	@Override
	public boolean next(LongWritable key, ObjectWritable value) throws IOException {
		if (!pcapReaderIterator.hasNext())
			return false;

		key.set(++packetCount);
		value.set(pcapReaderIterator.next());

		reporter.setStatus("Read " + getPos() + " of " + end + " bytes");
		reporter.progress();

		return true;
	}

	@Override
	public LongWritable createKey() {
		return new LongWritable();
	}

	@Override
	public ObjectWritable createValue() {
		return new ObjectWritable();
	}

	@Override
	public long getPos() throws IOException {
		return baseStream.getPos();
	}

	@Override
	public float getProgress() throws IOException {
		if (start == end)
			return 0;
		return Math.min(1.0f, (getPos() - start) / (float)(end - start));
	}
}