/**
 * @name haproxy-67dad2715ba73376995294d188ffb4242ce7fb0a-http_get_hdr
 * @id cpp/haproxy/67dad2715ba73376995294d188ffb4242ce7fb0a/http-get-hdr
 * @description haproxy-67dad2715ba73376995294d188ffb4242ce7fb0a-src/proto_http.c-http_get_hdr CVE-2013-2175
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vocc_8124, RelationalOperation target_2) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vocc_8124
		and target_0.getAnOperand().(Literal).getValue()="10"
		and target_0.getParent().(AssignAddExpr).getRValue() = target_0
		and target_2.getGreaterOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vocc_8124, VariableAccess target_1) {
		target_1.getTarget()=vocc_8124
		and target_1.getParent().(AssignAddExpr).getRValue() = target_1
}

predicate func_2(Parameter vocc_8124, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vocc_8124
}

from Function func, Parameter vocc_8124, VariableAccess target_1, RelationalOperation target_2
where
not func_0(vocc_8124, target_2)
and func_1(vocc_8124, target_1)
and func_2(vocc_8124, target_2)
and vocc_8124.getType().hasName("int")
and vocc_8124.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
