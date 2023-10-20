/**
 * @name libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-TPML_CC_Unmarshal
 * @id cpp/libtpms/2f30d620d3c053f20d38b54bf76ac0907821d263/TPML-CC-Unmarshal
 * @description libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-src/tpm2/Unmarshal.c-TPML_CC_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1854, RelationalOperation target_1, LogicalAndExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="count"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1854
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtarget_1854, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1854
		and target_1.getLesserOperand().(DivExpr).getValue()="254"
}

predicate func_2(Parameter vtarget_1854, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1854
}

from Function func, Parameter vtarget_1854, RelationalOperation target_1, LogicalAndExpr target_2
where
not func_0(vtarget_1854, target_1, target_2)
and func_1(vtarget_1854, target_1)
and func_2(vtarget_1854, target_2)
and vtarget_1854.getType().hasName("TPML_CC *")
and vtarget_1854.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
