/**
 * @name curl-192c4f788d48f82c03e9cef40013f34370e90737-Curl_urldecode
 * @id cpp/curl/192c4f788d48f82c03e9cef40013f34370e90737/Curl-urldecode
 * @description curl-192c4f788d48f82c03e9cef40013f34370e90737-lib/escape.c-Curl_urldecode CVE-2013-2174
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valloc_150, RelationalOperation target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=valloc_150
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_2.getGreaterOperand().(PrefixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vin_152, EqualityOperation target_1) {
		target_1.getAnOperand().(CharLiteral).getValue()="37"
		and target_1.getAnOperand().(VariableAccess).getTarget()=vin_152
}

predicate func_2(Variable valloc_150, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=valloc_150
		and target_2.getLesserOperand().(Literal).getValue()="0"
}

predicate func_3(Variable valloc_150, ExprStmt target_3) {
		target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=valloc_150
		and target_3.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
}

from Function func, Variable valloc_150, Variable vin_152, EqualityOperation target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(valloc_150, target_2, target_3)
and func_1(vin_152, target_1)
and func_2(valloc_150, target_2)
and func_3(valloc_150, target_3)
and valloc_150.getType().hasName("size_t")
and vin_152.getType().hasName("unsigned char")
and valloc_150.(LocalVariable).getFunction() = func
and vin_152.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
