package net.ripe.hadoop.pcap.packet;

import com.google.common.base.Objects;
import com.google.common.collect.ComparisonChain;

public class Flow implements Comparable<Flow> {
	private String src;
	private Integer srcPort;
	private String dst;
	private Integer dstPort;
	private String protocol;

	public Flow(String src, Integer srcPort, String dst, Integer dstPort, String protocol) {
		this.src = src;
		this.srcPort = srcPort;
		this.dst = dst;
		this.dstPort = dstPort;
		this.protocol = protocol;
	}

	@Override
	public int compareTo(Flow o) {
		return ComparisonChain.start()
		                      .compare(src, o.src)
		                      .compare(srcPort, o.srcPort)
		                      .compare(dst, o.dst)
		                      .compare(dstPort, o.dstPort)
		                      .compare(protocol, o.protocol)
		                      .result();
	}

	@Override
	public String toString() {
		return Objects.toStringHelper(this.getClass()).add("src", src)
		                                              .add("srcPort", srcPort)
		                                              .add("dst", dst)
		                                              .add("dstPort", dstPort)
		                                              .add("protocol", protocol)
		                                              .toString();
	}
}