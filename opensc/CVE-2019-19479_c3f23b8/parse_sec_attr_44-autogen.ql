/**
 * @name opensc-c3f23b836e5a1766c36617fe1da30d22f7b63de2-parse_sec_attr_44
 * @id cpp/opensc/c3f23b836e5a1766c36617fe1da30d22f7b63de2/parse-sec-attr-44
 * @description opensc-c3f23b836e5a1766c36617fe1da30d22f7b63de2-src/libopensc/card-setcos.c-parse_sec_attr_44 CVE-2019-19479
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable viACLen_791, RelationalOperation target_2) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=viACLen_791
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof SubExpr
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable viACLen_791, SubExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=viACLen_791
		and target_1.getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

predicate func_2(Variable viACLen_791, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=viACLen_791
		and target_2.getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable viACLen_791, SubExpr target_1, RelationalOperation target_2
where
not func_0(viACLen_791, target_2)
and func_1(viACLen_791, target_1)
and func_2(viACLen_791, target_2)
and viACLen_791.getType().hasName("size_t")
and viACLen_791.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
