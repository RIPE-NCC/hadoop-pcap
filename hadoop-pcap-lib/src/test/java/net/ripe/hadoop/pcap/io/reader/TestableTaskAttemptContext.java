package net.ripe.hadoop.pcap.io.reader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.mapreduce.TaskAttemptID;
import org.apache.hadoop.mapreduce.task.TaskAttemptContextImpl;

public class TestableTaskAttemptContext extends TaskAttemptContextImpl {
	private static final Log LOG = LogFactory.getLog(TestableTaskAttemptContext.class);

	public TestableTaskAttemptContext(Configuration conf) {
		super(conf, TaskAttemptID.forName("attempt_1_1_m_1_1"));
	}

	@Override
	public void progress() {
		// NOOP
	}

	@Override
	public void setStatus(String status) {
		LOG.debug(status);
	}
}