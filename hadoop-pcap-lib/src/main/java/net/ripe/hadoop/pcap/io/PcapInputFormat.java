package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.io.reader.PcapRecordReader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;

@SuppressWarnings("deprecation")
public class PcapInputFormat extends FileInputFormat<LongWritable, ObjectWritable> {
	public static final Log LOG = LogFactory.getLog(PcapInputFormat.class);

	@Override
	public RecordReader<LongWritable, ObjectWritable> getRecordReader(InputSplit split, JobConf config, Reporter reporter) throws IOException {
		FileSplit fileSplit = (FileSplit)split;
		Path filePath = fileSplit.getPath();

		LOG.info("Instantiate reader for: " + filePath);

		FileSystem fs = filePath.getFileSystem(config);
        FSDataInputStream baseStream = fs.open(filePath);

        DataInputStream is = baseStream;
		CompressionCodecFactory compressionCodecs = new CompressionCodecFactory(config);
        final CompressionCodec codec = compressionCodecs.getCodec(filePath);
        if (codec != null)
        	is = new DataInputStream(codec.createInputStream(is));

        PcapReader pcapReader = initPcapReader(is);
		return new PcapRecordReader(pcapReader, fileSplit, baseStream, is, reporter);
	}

	/**
	 * A PCAP can only be read as a whole. There is no way to know where
	 * to start reading in the middle of the file. It needs to be read
	 * from the beginning to the end.
	 * @see http://wiki.wireshark.org/Development/LibpcapFileFormat
	 */
	@Override
	protected boolean isSplitable(FileSystem fs, Path filename) {
		return false;
	}

	protected PcapReader initPcapReader(DataInputStream is) throws IOException {
		return new PcapReader(is);
	}
}