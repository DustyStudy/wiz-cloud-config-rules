package wiz_test

import future.keywords.if
import future.keywords.in

import data.wiz

perm(proto, from, to, cidr4, cidr6) := {
	"IpProtocol": proto, "FromPort": from, "ToPort": to,
	"IpRanges": [{"CidrIp": c} | some c in cidr4],
	"Ipv6Ranges": [{"CidrIpv6": c} | some c in cidr6],
}

sg(perms) := {"GroupId": "sg-1", "IpPermissions": perms}

test_ssh_from_office_passes if {
	wiz.result == "pass" with input as sg([perm("tcp", 22, 22, ["203.0.113.0/24"], [])])
}

test_https_public_passes if {
	wiz.result == "pass" with input as sg([perm("tcp", 443, 443, ["0.0.0.0/0"], ["::/0"])])
}

test_no_rules_passes if {
	wiz.result == "pass" with input as sg([])
}

test_permissions_absent_fails if {
	wiz.result == "fail" with input as {"GroupId": "sg-1"}
}

test_ssh_public_v4_fails if {
	wiz.result == "fail" with input as sg([perm("tcp", 22, 22, ["0.0.0.0/0"], [])])
}

test_rdp_public_v6_only_fails if {
	wiz.result == "fail" with input as sg([perm("tcp", 3389, 3389, [], ["::/0"])])
}

test_rdp_udp_fails if {
	wiz.result == "fail" with input as sg([perm("udp", 3389, 3389, ["0.0.0.0/0"], [])])
}

test_protocol_number_fails if {
	wiz.result == "fail" with input as sg([perm("6", 22, 22, ["0.0.0.0/0"], [])])
}

test_range_spanning_22_fails if {
	wiz.result == "fail" with input as sg([perm("tcp", 20, 25, ["0.0.0.0/0"], [])])
}

test_range_below_22_passes if {
	wiz.result == "pass" with input as sg([perm("tcp", 20, 21, ["0.0.0.0/0"], [])])
}

test_all_traffic_fails if {
	wiz.result == "fail" with input as sg([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
}

test_icmp_ignored_passes if {
	wiz.result == "pass" with input as sg([perm("icmp", 3, 22, ["0.0.0.0/0"], [])])
}

test_tcp_missing_ports_fails if {
	wiz.result == "fail" with input as sg([{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
}

test_camel_case_fails if {
	wiz.result == "fail" with input as {"ipPermissions": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}
}

test_fail_message if {
	wiz.currentConfiguration == "Ingress open to the internet on management port(s): 22." with input as sg([perm("tcp", 22, 22, ["0.0.0.0/0"], [])])
}

test_fail_message_both_ports if {
	wiz.currentConfiguration == "Ingress open to the internet on management port(s): 22, 3389." with input as sg([{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
}

test_permissions_null_fails if {
	wiz.result == "fail" with input as {"IpPermissions": null}
}

test_invalid_port_string_treated_as_open_fails if {
	wiz.result == "fail" with input as sg([{"IpProtocol": "TCP", "FromPort": "bad", "ToPort": "3389", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
}

test_string_ports_parse if {
	wiz.result == "pass" with input as sg([perm("tcp", "443", "443", ["0.0.0.0/0"], [])])
}

test_unavailable_message if {
	wiz.currentConfiguration == "Security group ingress rules are not available." with input as {"GroupId": "sg-1"}
}

test_missing_protocol_fails if {
	wiz.result == "fail" with input as sg([{"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
}

test_null_protocol_fails if {
	wiz.result == "fail" with input as sg([{"IpProtocol": null, "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
}
