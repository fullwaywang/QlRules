/**
 * @name openjpeg-e03e9474667e5117341351699f0b1dbb06f93346-opj_j2k_read_cbd
 * @id cpp/openjpeg/e03e9474667e5117341351699f0b1dbb06f93346/opj-j2k-read-cbd
 * @description openjpeg-e03e9474667e5117341351699f0b1dbb06f93346-src/lib/openjp2/j2k.c-opj_j2k_read_cbd CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="32"
		and not target_0.getValue()="31"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="prec"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Invalid values for comp = %d : prec=%u (should be between 1 and 38 according to the JPEG2000 norm. OpenJpeg only supports up to 32)\n"
		and not target_1.getValue()="Invalid values for comp = %d : prec=%u (should be between 1 and 38 according to the JPEG2000 norm. OpenJpeg only supports up to 31)\n"
		and target_1.getEnclosingFunction() = func
}

from Function func, Literal target_0, StringLiteral target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
