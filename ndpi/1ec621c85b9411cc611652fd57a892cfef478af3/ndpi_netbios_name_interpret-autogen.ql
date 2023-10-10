/**
 * @name ndpi-1ec621c85b9411cc611652fd57a892cfef478af3-ndpi_netbios_name_interpret
 * @id cpp/ndpi/1ec621c85b9411cc611652fd57a892cfef478af3/ndpi-netbios-name-interpret
 * @description ndpi-1ec621c85b9411cc611652fd57a892cfef478af3-src/lib/protocols/netbios.c-ndpi_netbios_name_interpret CVE-2021-36082
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vin_len_41, LogicalOrExpr target_2) {
	exists(CommaExpr target_0 |
		target_0.getLeftOperand() instanceof AssignExpr
		and target_0.getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vin_len_41
		and target_0.getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vin_41, Variable vlen_42, AssignExpr target_1) {
		target_1.getLValue().(VariableAccess).getTarget()=vlen_42
		and target_1.getRValue().(DivExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vin_41
		and target_1.getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_2(Parameter vin_len_41, Variable vlen_42, LogicalOrExpr target_2) {
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_42
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_42
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vlen_42
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vin_len_41
}

from Function func, Parameter vin_41, Parameter vin_len_41, Variable vlen_42, AssignExpr target_1, LogicalOrExpr target_2
where
not func_0(vin_len_41, target_2)
and func_1(vin_41, vlen_42, target_1)
and func_2(vin_len_41, vlen_42, target_2)
and vin_41.getType().hasName("char *")
and vin_len_41.getType().hasName("size_t")
and vlen_42.getType().hasName("u_int")
and vin_41.getParentScope+() = func
and vin_len_41.getParentScope+() = func
and vlen_42.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
