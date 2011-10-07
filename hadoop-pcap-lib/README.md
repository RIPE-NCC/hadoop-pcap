Usage
-----

### Example: Count source ports

	public class Pcap extends Configured implements Tool {
		public int run(String[] args) throws Exception {
			JobConf conf = new JobConf(getConf(), Pcap.class);
			conf.setJobName("Pcap");
	
			conf.setOutputKeyClass(IntWritable.class);
			conf.setOutputValueClass(LongWritable.class);
	
			conf.setInputFormat(PcapInputFormat.class);
	
			conf.setMapperClass(PcapMapper.class);
			conf.setReducerClass(PcapReducer.class);
	
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
