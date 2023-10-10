/**
 * @name libpcap-a5a36d9e82dde7265e38fe1f87b7f11c461c29f6-pcap_ng_check_header
 * @id cpp/libpcap/a5a36d9e82dde7265e38fe1f87b7f11c461c29f6/pcap-ng-check-header
 * @description libpcap-a5a36d9e82dde7265e38fe1f87b7f11c461c29f6-sf-pcapng.c-pcap_ng_check_header CVE-2019-15165
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Section Header Block in pcapng dump file has invalid length %zu < _%lu_ < %lu (BT_SHB_INSANE_MAX)"
		and not target_0.getValue()="Section Header Block in pcapng dump file has invalid length %zu < _%u_ < %u (BT_SHB_INSANE_MAX)"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
