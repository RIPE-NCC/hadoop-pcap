Limitations
-----------

This SerDe currently only supports deserialization of PCAPs.
We use *HiveIgnoreKeyTextOutputFormat* to disable serialization in the *OUTPUTFORMAT* paramters below.


Usage
-----

**Important** Do not forget to add the library before trying the examples below:

	ADD JAR hadoop-pcap-serde-0.1-jar-with-dependencies.jar;


You can use the following parameters to combine multiple input files into splits of 100MB in size:

	SET hive.input.format=org.apache.hadoop.hive.ql.io.CombineHiveInputFormat;
	SET mapred.max.split.size=104857600;

### DNS table on HDFS

	SET net.ripe.hadoop.pcap.io.reader.class=net.ripe.hadoop.pcap.DnsPcapReader;

	CREATE EXTERNAL TABLE pcaps (ts bigint,
	                             ts_usec decimal,
	                             protocol string,
	                             src string,
	                             src_port int,
	                             dst string,
	                             dst_port int,
	                             len int,
	                             ttl int,
	                             dns_queryid int,
	                             dns_flags string,
	                             dns_opcode string,
	                             dns_rcode string,
	                             dns_question string,
	                             dns_answer array<string>,
	                             dns_authority array<string>,
	                             dns_additional array<string>)
	ROW FORMAT SERDE 'net.ripe.hadoop.pcap.serde.PcapDeserializer'
	STORED AS INPUTFORMAT 'net.ripe.hadoop.pcap.io.PcapInputFormat'
	          OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
	LOCATION 'hdfs:///pcaps/';


### PCAP table on Amazon S3

	CREATE EXTERNAL TABLE pcaps (ts bigint,
	                             protocol string,
	                             src string,
	                             src_port int,
	                             dst string,
	                             dst_port int,
	                             len int,
	                             ttl int)
	ROW FORMAT SERDE 'net.ripe.hadoop.pcap.serde.PcapDeserializer' 
	STORED AS INPUTFORMAT 'net.ripe.hadoop.pcap.io.PcapInputFormat' 
	          OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat' 
	LOCATION 's3n://pcaps/';
