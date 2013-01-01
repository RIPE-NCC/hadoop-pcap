package net.ripe.hadoop.pcap.serde;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.ripe.hadoop.pcap.packet.Packet;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.serde.Constants;
import org.apache.hadoop.hive.serde2.Deserializer;
import org.apache.hadoop.hive.serde2.SerDeException;
import org.apache.hadoop.hive.serde2.SerDeStats;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfo;
import org.apache.hadoop.hive.serde2.typeinfo.TypeInfoUtils;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.Writable;

public class PcapDeserializer implements Deserializer {
	ObjectInspector inspector;
	ArrayList<Object> row;
	int numColumns;
	List<String> columnNames;
	
	@Override
	public SerDeStats getSerDeStats() {
		//We collect no statistics.
		return new SerDeStats();
	}

	@Override
	public void initialize(Configuration cfg, Properties props) throws SerDeException {		
		String columnNameProperty = props.getProperty(Constants.LIST_COLUMNS);
		columnNames = Arrays.asList(columnNameProperty.split(","));
		numColumns = columnNames.size();

		String columnTypeProperty = props.getProperty(Constants.LIST_COLUMN_TYPES);
		List<TypeInfo> columnTypes = TypeInfoUtils.getTypeInfosFromTypeString(columnTypeProperty);

		// Ensure we have the same number of column names and types
		assert numColumns == columnTypes.size();

        List<ObjectInspector> inspectors = new ArrayList<ObjectInspector>(numColumns);
        row = new ArrayList<Object>(numColumns);
        for (int c = 0; c < numColumns; c++) {
        	ObjectInspector oi = TypeInfoUtils.getStandardJavaObjectInspectorFromTypeInfo(columnTypes.get(c));
            inspectors.add(oi);
            row.add(null);
        }
        inspector = ObjectInspectorFactory.getStandardStructObjectInspector(columnNames, inspectors);
	}

	@Override
	public Object deserialize(Writable w) throws SerDeException {
		ObjectWritable obj = (ObjectWritable)w;
		Packet packet = (Packet)obj.get();

        for (int i = 0; i < numColumns; i++) {
            String columName = columnNames.get(i);
            Object value = packet.get(columName);
           	row.set(i, value);
        }
        return row;
	}

	@Override
	public ObjectInspector getObjectInspector() throws SerDeException {
		return inspector;
	}
}