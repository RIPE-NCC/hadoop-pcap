package net.ripe.hadoop.pcap.io;

import java.io.IOException;

import net.ripe.hadoop.pcap.io.reader.CombinePcapRecordReader;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.lib.CombineFileInputFormat;
import org.apache.hadoop.mapred.lib.CombineFileRecordReader;
import org.apache.hadoop.mapred.lib.CombineFileSplit;

@SuppressWarnings("deprecation")
public class CombinePcapInputFormat extends CombineFileInputFormat<LongWritable, ObjectWritable> {
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public RecordReader<LongWritable, ObjectWritable> getRecordReader(InputSplit split, JobConf job, Reporter reporter) throws IOException {
		return new CombineFileRecordReader(job, (CombineFileSplit)split, reporter, CombinePcapRecordReader.class);
	}

	/**
	 * A PCAP can only be read as a whole. There is no way to know where to
	 * start reading in the middle of the file. It needs to be read from the
	 * beginning to the end.
	 * @see http://wiki.wireshark.org/Development/LibpcapFileFormat
	 */
	@Override
	protected boolean isSplitable(FileSystem fs, Path filename) {
		return false;
	}
}
