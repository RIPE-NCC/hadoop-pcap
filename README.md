Hadoop PCAP library
===================

License
-------
This library is distributed under the LGPL.
See: https://raw.github.com/RIPE-NCC/hadoop-pcap/master/LICENSE


Download
--------

* 0.1: https://s3-eu-west-1.amazonaws.com/hadoop-pcap/hadoop-pcap-serde-0.1-jar-with-dependencies.jar (Released 07/10/2011)


Usage
-----

**Important** Do not forget to add the library before trying the examples below:

	ADD JAR hadoop-pcap-serde-0.1-jar-with-dependencies.jar;


### DNS table on HDFS

	CREATE EXTERNAL TABLE pcaps (ts bigint,
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
	STORED AS INPUTFORMAT 'net.ripe.hadoop.pcap.io.DnsPcapInputFormat'
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
