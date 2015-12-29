package net.ripe.hadoop.pcap.io.reader;

import java.io.IOException;
import java.util.Iterator;

import net.ripe.hadoop.pcap.io.PcapInputFormat;

import net.ripe.hadoop.pcap.packet.Packet;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.lib.input.CombineFileSplit;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

/**
 * Wrapper for CombineFileSplit to RecordReader
 * @author wnagele
 */
public class CombinePcapRecordReader extends RecordReader<LongWritable, ObjectWritable> {
	private PcapRecordReader recordReader;
    private Iterator<Packet> pcapReaderIterator;
    private TaskAttemptContext conf;
    private FileSplit fileSplit;
    private LongWritable key;
    private ObjectWritable value;
    private Long packetCount = 0L;

	public CombinePcapRecordReader(CombineFileSplit split, TaskAttemptContext context, Integer index) throws IOException {
		Path path = split.getPath(index);
		long start = 0L;
		long length = split.getLength(index);
		recordReader = PcapInputFormat.initPcapRecordReader(path, start, length, context);
	}

    @Override
    public void initialize(InputSplit inputSplit, TaskAttemptContext taskAttemptContext)
            throws IOException, InterruptedException {
        this.fileSplit = (FileSplit) inputSplit;
        this.conf = taskAttemptContext;
    }

	@Override
	public boolean nextKeyValue() throws IOException {
		return recordReader.nextKeyValue();
	}

    @Override
    public LongWritable getCurrentKey() {
        return key;
    }

	@Override
	public ObjectWritable getCurrentValue() {
		return value;
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