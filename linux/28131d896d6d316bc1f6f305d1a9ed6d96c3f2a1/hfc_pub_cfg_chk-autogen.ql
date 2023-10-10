/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-hfc_pub_cfg_chk
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/hfc-pub-cfg-chk
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-hfc_pub_cfg_chk CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="14"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-14"
		and target_1.getOperand().(Literal).getValue()="14"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vpub_cfg_560) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="grp0"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpub_cfg_560
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="grp1"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpub_cfg_560
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pub_max"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpub_cfg_560)
}

from Function func, Variable vpub_cfg_560
where
func_0(func)
and not func_1(func)
and func_2(vpub_cfg_560)
and vpub_cfg_560.getType().hasName("const rtw89_hfc_pub_cfg *")
and vpub_cfg_560.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
