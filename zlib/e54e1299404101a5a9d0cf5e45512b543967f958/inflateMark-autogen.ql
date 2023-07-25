/**
 * @name zlib-e54e1299404101a5a9d0cf5e45512b543967f958-inflateMark
 * @id cpp/zlib/e54e1299404101a5a9d0cf5e45512b543967f958/inflateMark
 * @description zlib-e54e1299404101a5a9d0cf5e45512b543967f958-inflate.c-inflateMark CVE-2016-9842
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BinaryBitwiseOperation target_0 |
		target_0.getValue()="18446744073709486080"
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Function func, BinaryBitwiseOperation target_2) {
		target_2.getValue()="-65536"
		and target_2.getEnclosingFunction() = func
}

from Function func, BinaryBitwiseOperation target_2
where
not func_0(func)
and func_2(func, target_2)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
