package net.ripe.hadoop.pcap.io.reader;

import java.io.IOException;

import net.ripe.hadoop.pcap.io.PcapInputFormat;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.lib.CombineFileSplit;

/**
 * Wrapper for CombineFileSplit to RecordReader
 * @author wnagele
 */
public class CombinePcapRecordReader implements RecordReader<LongWritable, ObjectWritable> {
	private PcapRecordReader recordReader;

	public CombinePcapRecordReader(CombineFileSplit split, Configuration conf, Reporter reporter, Integer index) throws IOException {
		Path path = split.getPath(index);
		long start = 0L;
		long length = split.getLength(index);
		recordReader = PcapInputFormat.initPcapRecordReader(path, start, length, reporter, conf);
	}

	@Override
	public boolean next(LongWritable key, ObjectWritable value) throws IOException {
		return recordReader.next(key, value);
	}

	@Override
	public LongWritable createKey() {
		return recordReader.createKey();
	}

	@Override
	public ObjectWritable createValue() {
		return recordReader.createValue();
	}

	@Override
	public long getPos() throws IOException {
		return recordReader.getPos();
	}

	@Override
	public void close() throws IOException {
		recordReader.close();
	}

	@Override
	public float getProgress() throws IOException {
		return recordReader.getProgress();
	}
}