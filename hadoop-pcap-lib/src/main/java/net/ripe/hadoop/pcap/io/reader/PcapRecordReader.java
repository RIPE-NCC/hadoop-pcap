package net.ripe.hadoop.pcap.io.reader;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

public class PcapRecordReader extends RecordReader<LongWritable, ObjectWritable> {
    PcapReader pcapReader;
    Iterator<Packet> pcapReaderIterator;
    Seekable baseStream;
    DataInputStream stream;

    private LongWritable key = new LongWritable();
    private ObjectWritable value = new ObjectWritable();
    private FileSplit fileSplit;
    private Configuration conf;

    long packetCount = 0;
    long start, end;

    public PcapRecordReader(PcapReader pcapReader, long start, long end, Seekable baseStream, DataInputStream stream) throws IOException {
        this.pcapReader = pcapReader;
        this.baseStream = baseStream;
        this.stream = stream;
        this.start = start;
        this.end = end;

        pcapReaderIterator = pcapReader.iterator();
    }

    @Override
    public void initialize(InputSplit inputSplit, TaskAttemptContext taskAttemptContext)
            throws IOException, InterruptedException {
        this.fileSplit = (FileSplit) inputSplit;
        this.conf = taskAttemptContext.getConfiguration();
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }

    @Override
    public boolean nextKeyValue() throws IOException {
        if (!pcapReaderIterator.hasNext())
            return false;

        this.key.set(++packetCount);
        value.set(pcapReaderIterator.next());

        return true;
    }

    @Override
    public ObjectWritable getCurrentValue() {
        return (ObjectWritable)value;
    }

    @Override
    public LongWritable getCurrentKey() {
        return key;
    }

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
