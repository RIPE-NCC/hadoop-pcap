package net.ripe.hadoop.pcap.packet;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ComparisonChain;
import com.google.common.collect.Ordering;

public class Flow implements Comparable<Flow> {
	private final String src;
	private final Integer srcPort;
	private final String dst;
	private final Integer dstPort;
	private final String protocol;

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
		                      .compare(src, o.src, Ordering.natural().nullsLast())
		                      .compare(srcPort, o.srcPort, Ordering.natural().nullsLast())
		                      .compare(dst, o.dst, Ordering.natural().nullsLast())
		                      .compare(dstPort, o.dstPort, Ordering.natural().nullsLast())
		                      .compare(protocol, o.protocol, Ordering.natural().nullsLast())
		                      .result();
	}

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this.getClass()).add("src", src)
		                                              .add("srcPort", srcPort)
		                                              .add("dst", dst)
		                                              .add("dstPort", dstPort)
		                                              .add("protocol", protocol)
		                                              .toString();
	}
}
