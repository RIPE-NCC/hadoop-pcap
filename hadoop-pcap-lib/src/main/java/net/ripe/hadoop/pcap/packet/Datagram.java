package net.ripe.hadoop.pcap.packet;

import com.google.common.base.Objects;
import com.google.common.collect.ComparisonChain;

public class Datagram implements Comparable<Datagram> {
	private String src;
	private String dst;
	private Long id;
	private String protocol;

	public Datagram(String src, String dst, Long id, String protocol) {
		this.src = src;
		this.dst = dst;
		this.id = id;
		this.protocol = protocol;
	}

	@Override
	public int compareTo(Datagram o) {
		return ComparisonChain.start()
		                      .compare(src, o.src)
		                      .compare(dst, o.dst)
		                      .compare(id, o.id)
		                      .compare(protocol, o.protocol)
		                      .result();
	}

	@Override
	public String toString() {
		return Objects.toStringHelper(this.getClass()).add("src", src)
		                                              .add("dst", dst)
		                                              .add("id", id)
		                                              .add("protocol", protocol)
		                                              .toString();
	}
}