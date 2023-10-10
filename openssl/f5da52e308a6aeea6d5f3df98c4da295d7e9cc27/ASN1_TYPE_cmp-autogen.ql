/**
 * @name openssl-f5da52e308a6aeea6d5f3df98c4da295d7e9cc27-ASN1_TYPE_cmp
 * @id cpp/openssl/f5da52e308a6aeea6d5f3df98c4da295d7e9cc27/ASN1-TYPE-cmp
 * @description openssl-f5da52e308a6aeea6d5f3df98c4da295d7e9cc27-ASN1_TYPE_cmp CVE-2016-2108
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SwitchCase target_0 |
		target_0.getExpr().(BitwiseOrExpr).getValue()="258"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(SwitchCase target_1 |
		target_1.getExpr().(BitwiseOrExpr).getValue()="266"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
