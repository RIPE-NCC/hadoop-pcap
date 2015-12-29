package net.ripe.hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.io.reader.PcapRecordReader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.TaskAttemptContext;

public class PcapInputFormat extends org.apache.hadoop.mapreduce.lib.input.FileInputFormat<LongWritable, ObjectWritable> {
    static final String READER_CLASS_PROPERTY = "net.ripe.hadoop.pcap.io.reader.class";

    public static final Log LOG = LogFactory.getLog(PcapInputFormat.class);

    public org.apache.hadoop.mapreduce.RecordReader<LongWritable, ObjectWritable> createRecordReader(org.apache.hadoop.mapreduce.InputSplit split, TaskAttemptContext context) throws IOException, InterruptedException {
        FileSplit fileSplit = (FileSplit)split;
        Path path = fileSplit.getPath();
        LOG.info("Reading PCAP: " + path.toString());
        long start = 0L;
        long length = fileSplit.getLength();
        return initPcapRecordReader(path, start, length, context);
    }

    public static PcapRecordReader initPcapRecordReader(Path path, long start, long length, TaskAttemptContext context) throws IOException {
        Configuration conf = context.getConfiguration();
        FileSystem fs = path.getFileSystem(conf);
        FSDataInputStream baseStream = fs.open(path);
        DataInputStream stream = baseStream;
        CompressionCodecFactory compressionCodecs = new CompressionCodecFactory(conf);
        final CompressionCodec codec = compressionCodecs.getCodec(path);
        if (codec != null)
            stream = new DataInputStream(codec.createInputStream(stream));

        PcapReader reader = initPcapReader(stream, conf);
        return new PcapRecordReader(reader, start, length, baseStream, stream);
    }

    public static PcapReader initPcapReader(DataInputStream stream, Configuration conf) {
        try {
            Class<? extends PcapReader> pcapReaderClass = conf.getClass(READER_CLASS_PROPERTY, PcapReader.class, PcapReader.class);
            Constructor<? extends PcapReader> pcapReaderConstructor = pcapReaderClass.getConstructor(DataInputStream.class);
            return pcapReaderConstructor.newInstance(stream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected boolean isSplitable(JobContext context, Path filename) {
        return false;
    }
}
