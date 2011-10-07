Hadoop PCAP library
===================

License
-------
This library is distributed under the LGPL.  
See: https://raw.github.com/RIPE-NCC/hadoop-pcap/master/LICENSE


Download
--------

### Version 0.1

Release date: 07/10/2011  
Download link: https://github.com/downloads/RIPE-NCC/hadoop-pcap/hadoop-pcap-serde-0.1-jar-with-dependencies.jar  
MD5 sum: 2729bbfa4df3cd617aba4aa034e96fd0  
SHA1 sum: 763e98a6a0878ffbb79961fbea6979e27064caef


Screencast
----------

We have created a screencast showing the use of the Hadoop PCAP SerDe in Hive using [Amazon Elastic MapReduce](http://aws.amazon.com/elasticmapreduce/).  
You can find the video on YouTube: http://www.youtube.com/watch?v=Wqm79ML-xQs


Components
----------

This project consists of two components:

### Library

Bundles the code used to read PCAPs. Can be used within MapReduce jobs to natively read PCAP files.  
See: https://github.com/RIPE-NCC/hadoop-pcap/tree/master/hadoop-pcap-lib

### SerDe

Implements a Hive Serializer/Deserializer (SerDe) to query PCAPs using SQL like commands.  
See: https://github.com/RIPE-NCC/hadoop-pcap/tree/master/hadoop-pcap-serde
