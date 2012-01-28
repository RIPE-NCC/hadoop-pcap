Configure reader
----------------
You can adjust the reader used to decode the packet by adjusting the property ``net.ripe.hadoop.pcap.io.reader.class``.
The default value for this property is the class ``net.ripe.hadoop.pcap.PcapReader``.

Write a reader for other protocols
----------------------------------
You might want to decode packets that carry other protocols. Currently this library has readers for plain IP packets and packets carrying DNS payloads.

As mentioned in the section ``Configure reader`` above you can configure which reader class you would like to use by simply changing the value of a property.

The class ``net.ripe.hadoop.pcap.DnsPcapReader`` is an example that shows how to write such a reader.
You need to override two methods and define a packet format by creating your own implementation like ``net.ripe.hadoop.pcap.packet.DnsPacket`` does.

We would be happy to include your reader implementations in this library if you develop them. Send us a pull request on GitHub.

Usage
-----

### Example: Count source ports

	public class Pcap extends Configured implements Tool {
		public int run(String[] args) throws Exception {
			JobConf conf = new JobConf(getConf(), Pcap.class);
			conf.setJobName("Pcap");
	
			conf.setOutputKeyClass(IntWritable.class);
			conf.setOutputValueClass(LongWritable.class);
	
			conf.setInputFormat(CombinePcapInputFormat.class);
	
			conf.setMapperClass(PcapMapper.class);
			conf.setReducerClass(PcapReducer.class);

			// Combine input files into splits of 100MB in size
			conf.setLong("mapred.max.split.size", 104857600);
	
			FileInputFormat.addInputPath(conf, new Path("input"));
			FileOutputFormat.setOutputPath(conf, new Path("output"));
	
			return JobClient.runJob(conf).isSuccessful() ? 0 : 1;
		}
	
		public Pcap() {
			super(new Configuration());
		}
	
		public static void main(String[] args) throws Exception {
			int res = ToolRunner.run(new Pcap(), args);
			System.exit(res);
		}
	}


	public class PcapMapper extends MapReduceBase implements Mapper<LongWritable, ObjectWritable, IntWritable, LongWritable> {
		private final static LongWritable ONE = new LongWritable(1);
		private IntWritable srcPort = new IntWritable();
	
		@Override
		public void map(LongWritable key, ObjectWritable value, OutputCollector<IntWritable, LongWritable> output, Reporter reporter) throws IOException {
			Packet packet = (Packet)value.get();
			if (packet != null) {
				Object srcPortVal = packet.get(Packet.SRC_PORT);
				if (srcPortVal != null) {
					srcPort.set((Integer)srcPortVal);
					output.collect(srcPort, ONE);
				}
			}
		}
	}


	public class PcapReducer extends MapReduceBase implements Reducer<IntWritable, LongWritable, IntWritable, LongWritable> {
		public void reduce(IntWritable key, Iterator<LongWritable> values, OutputCollector<IntWritable, LongWritable> output, Reporter reporter) throws IOException {
			long sum = 0;
			while (values.hasNext())
				sum += values.next().get();
	
			output.collect(key, new LongWritable(sum));
		}
	}