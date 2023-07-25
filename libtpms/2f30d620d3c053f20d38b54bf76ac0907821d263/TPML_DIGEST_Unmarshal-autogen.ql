/**
 * @name libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-TPML_DIGEST_Unmarshal
 * @id cpp/libtpms/2f30d620d3c053f20d38b54bf76ac0907821d263/TPML-DIGEST-Unmarshal
 * @description libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-src/tpm2/Unmarshal.c-TPML_DIGEST_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1967, RelationalOperation target_2, RelationalOperation target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="count"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1967
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtarget_1967, RelationalOperation target_3, LogicalAndExpr target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="count"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1967
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtarget_1967, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1967
		and target_2.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_3(Parameter vtarget_1967, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1967
		and target_3.getLesserOperand().(Literal).getValue()="8"
}

predicate func_4(Parameter vtarget_1967, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1967
}

from Function func, Parameter vtarget_1967, RelationalOperation target_2, RelationalOperation target_3, LogicalAndExpr target_4
where
not func_0(vtarget_1967, target_2, target_3)
and not func_1(vtarget_1967, target_3, target_4)
and func_2(vtarget_1967, target_2)
and func_3(vtarget_1967, target_3)
and func_4(vtarget_1967, target_4)
and vtarget_1967.getType().hasName("TPML_DIGEST *")
and vtarget_1967.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
