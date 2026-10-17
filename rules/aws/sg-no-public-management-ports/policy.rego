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

# TCP and UDP (RDP also listens on UDP 3389), by name or protocol number.
port_protocols := {"tcp", "6", "udp", "17"}

all_protocols := {"-1", "all"}

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
	from := to_number(fieldd(p, "FromPort", "fromPort", 0))
	to := to_number(fieldd(p, "ToPort", "toPort", 65535))
	from <= port
	port <= to
}

exposed := {port |
	some p in fieldd(input, "IpPermissions", "ipPermissions", [])
	public(p)
	some port in management_ports
	reaches(p, port)
}

default result := "pass"

result := "fail" if count(exposed) > 0

currentConfiguration := sprintf("Ingress open to the internet on management port(s): %s.", [concat(", ", [sprintf("%v", [x]) | some x in sort(exposed)])]) if result == "fail"

expectedConfiguration := "No ingress rule allows 0.0.0.0/0 or ::/0 to reach port 22 or 3389 (TCP or UDP) or all traffic."
