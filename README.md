# fw-regex
Python module with common regexps and methods for processing firewall log messages.

Both the timestamp format and message format can differ between different firewall vendors and different syslog servers, so there is a need to parse those messages in a robust way. This module has methods to parse messages and return normalized dictionaries regardless of firewall vendor or syslog timestamp configuration.

## Methods

### get_timestamp(line)

Extracts timestamp based on regex matching of several possible
timestamp formats.

#### Args:
 * line: String, the syslog message to parse

#### Returns:
 * Dictionary with the fields [year, month, day, time]. Contents of each field is a String with extracted timestamp data.

Note that "year" field may be None if timestamp does not include that information (which "RSYSLOG_TraditionalFileFormat" does not).

If unable to extract timestamp, None is returned instead of a dict.

### get_builtconn(line)

Extracts connection info based on regex matching of several possible syslog formats used by different types of devices.

#### Args:
 * line: String, the syslog message to parse

#### Returns:
 * Dictionary with the following fields: [direction, protocol, src, sport, interface_in, dst, dport, interface_out]. Contents of each field is a String with extracted data or None if not found.

If unable to extract connection info, None is returned instead of a dict.
