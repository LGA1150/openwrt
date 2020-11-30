local m, s, o

if luci.sys.call("pidof chinadns-ng >/dev/null") == 0 then
	m = Map("chinadns-ng", translate("ChinaDNS-NG"), "%s - %s" %{translate("ChinaDNS-NG"), translate("RUNNING")})
else
	m = Map("chinadns-ng", translate("ChinaDNS-NG"), "%s - %s" %{translate("ChinaDNS-NG"), translate("NOT RUNNING")})
end

s = m:section(TypedSection, "chinadns-ng", translate("General Setting"))
s.anonymous   = true

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty     = false

o = s:option(Flag, "fair_mode",
	translate("Enable the Fair_Mode"),
	translate("Enable the Fair_Mode or use the Compete_Mode"))
o.rmempty     = false

o = s:option(Value, "bind_port", translate("Listen Port"))
o.placeholder = 65353
o.datatype    = "port"
o.rmempty     = true

o = s:option(Value, "bind_addr", translate("Listen Address"))
o.placeholder = "127.0.0.1"
o.datatype    = "ipaddr"
o.rmempty     = true

o = s:option(Value, "chnlist_file", translate("CHN Domain List File"))
o.placeholder = "/etc/chinadns-ng/chinalist.txt"
o.datatype    = "file"
o.rmempty     = true

o = s:option(Value, "gfwlist_file", translate("GFW Domain List File"))
o.placeholder = "/etc/chinadns-ng/gfwlist.txt"
o.datatype    = "file"
o.rmempty     = true

o = s:option(Value, "ipset_name4", translate("CHNRoute IPSet Name (IPv4)"))
o.placeholder = "chnroute"
o.rmempty     = true

o = s:option(Value, "ipset_name6", translate("CHNRoute IPSet Name (IPv6)"))
o.placeholder = "chnroute6"
o.rmempty     = true

o = s:option(Value, "timeout_sec", translate("timeout_sec"))
o.placeholder = "5"
o.datatype    = "uinteger"
o.rmempty     = true

o = s:option(Value, "repeat_times", translate("repeat_times"))
o.placeholder = "1"
o.datatype    = "uinteger"
o.rmempty     = true

o = s:option(Value, "china_dns",
	translate("China DNS Servers"),
	translate("Use commas to separate multiple ip address, Max 2 Servers"))
o.placeholder = "114.114.114.114"
o.default     = "114.114.114.114"
o.rmempty     = false

o = s:option(Value, "trust_dns",
	translate("Trusted DNS Servers"),
	translate("Use commas to separate multiple ip address, Max 2 Servers"))
o.placeholder = "127.0.0.1#5300"
o.default     = "127.0.0.1#5300"
o.rmempty     = false

o = s:option(Flag, "chnlist_first",
	translate("match chnlist first"),
	translate("match chnlist first, default is gfwfirst"))
o.rmempty     = true

o = s:option(Flag, "reuse_port",
	translate("reuse_port"),
	translate("reuse_port, for Multi-process load balancing"))
o.rmempty     = true

o = s:option(Flag, "noip_as_chnip",
	translate("accept no ip"),
	translate("accept reply without ipaddr (A/AAAA query)"))
o.rmempty     = true

return m
