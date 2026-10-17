package wiz

import future.keywords.if
import future.keywords.in

# field returns obj[pascal] if present (even false/null), else obj[camel]; undefined if neither.
field(obj, pascal, camel) := v if {
	v := obj[pascal]
} else := v if {
	v := obj[camel]
}

# fieldd is field with a default when neither key exists or the value is null.
fieldd(obj, pascal, camel, d) := v if {
	v := field(obj, pascal, camel)
	v != null
} else := d

management_ports := [22, 3389]

# num converts to a number, or returns d when the value cannot be parsed (fail closed: d widens the range).
num(x, d) := n if {
	n := to_number(x)
} else := d

# Absent or null ingress data is unknown, not "no rules".
permissions := field(input, "IpPermissions", "ipPermissions")

permissions_known if is_array(permissions)

# TCP and UDP (RDP also listens on UDP 3389), by name or protocol number.
port_protocols := {"tcp", "6", "udp", "17"}

# A missing protocol is unknown, so it is treated as all traffic (fail closed).
all_protocols := {"-1", "all", ""}

public(p) if {
	some r in fieldd(p, "IpRanges", "ipRanges", [])
	fieldd(r, "CidrIp", "cidrIp", "") == "0.0.0.0/0"
}

public(p) if {
	some r in fieldd(p, "Ipv6Ranges", "ipv6Ranges", [])
	fieldd(r, "CidrIpv6", "cidrIpv6", "") == "::/0"
}

protocol(p) := lower(sprintf("%v", [fieldd(p, "IpProtocol", "ipProtocol", "")]))

reaches(p, _) if protocol(p) in all_protocols

# Missing port fields on a TCP/UDP rule are treated as the full port range.
reaches(p, port) if {
	protocol(p) in port_protocols
	from := num(fieldd(p, "FromPort", "fromPort", 0), 0)
	to := num(fieldd(p, "ToPort", "toPort", 65535), 65535)
	from <= port
	port <= to
}

exposed := {port |
	some p in permissions
	public(p)
	some port in management_ports
	reaches(p, port)
}

default result := "pass"

result := "fail" if {
	not permissions_known
} else := "fail" if {
	count(exposed) > 0
}

currentConfiguration := "Security group ingress rules are not available." if {
	result == "fail"
	not permissions_known
} else := sprintf("Ingress open to the internet on management port(s): %s.", [concat(", ", [sprintf("%v", [x]) | some x in sort(exposed)])]) if {
	result == "fail"
}

expectedConfiguration := "No ingress rule allows 0.0.0.0/0 or ::/0 to reach port 22 or 3389 (TCP or UDP) or all traffic."
