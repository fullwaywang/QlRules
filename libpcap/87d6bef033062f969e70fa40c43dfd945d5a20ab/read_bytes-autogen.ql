/**
 * @name libpcap-87d6bef033062f969e70fa40c43dfd945d5a20ab-read_bytes
 * @id cpp/libpcap/87d6bef033062f969e70fa40c43dfd945d5a20ab/read-bytes
 * @description libpcap-87d6bef033062f969e70fa40c43dfd945d5a20ab-sf-pcapng.c-read_bytes CVE-2019-15165
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="truncated dump file; tried to read %zu bytes, only got %zu"
		and not target_0.getValue()="truncated pcapng dump file; tried to read %zu bytes, only got %zu"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
