package net.ripe.hadoop.pcap.io.reader;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;

public class PcapRecordReader extends RecordReader<LongWritable, ObjectWritable> {
    PcapReader pcapReader;
    Iterator<Packet> pcapReaderIterator;
    Seekable baseStream;
    DataInputStream stream;
    TaskAttemptContext context;

    private LongWritable key = new LongWritable();
    private ObjectWritable value = new ObjectWritable();

    long packetCount = 0;
    long start, end;

    public PcapRecordReader(PcapReader pcapReader, long start, long end, Seekable baseStream, DataInputStream stream, TaskAttemptContext context) throws IOException {
        this.pcapReader = pcapReader;
        this.baseStream = baseStream;
        this.stream = stream;
        this.context = context;
        this.start = start;
        this.end = end;

        pcapReaderIterator = pcapReader.iterator();
    }

    @Override
    public void initialize(InputSplit inputSplit, TaskAttemptContext taskAttemptContext) throws IOException, InterruptedException {}

    @Override
    public void close() throws IOException {
        stream.close();
    }

    @Override
    public boolean nextKeyValue() throws IOException {
        if (!pcapReaderIterator.hasNext())
            return false;

        key.set(++packetCount);
        value.set(pcapReaderIterator.next());

        context.setStatus("Read " + getPos() + " of " + end + " bytes");
        context.progress();

        return true;
    }

    @Override
    public ObjectWritable getCurrentValue() {
        return value;
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
