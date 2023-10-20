/**
 * @name expat-ede41d1e186ed2aba88a06e84cac839b770af3a1-doProlog
 * @id cpp/expat/ede41d1e186ed2aba88a06e84cac839b770af3a1/doProlog
 * @description expat-ede41d1e186ed2aba88a06e84cac839b770af3a1-expat/lib/xmlparse.c-doProlog CVE-2022-23990
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vdtd_4496, Variable vnameLen_5375, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, ArrayExpr target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnameLen_5375
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getValue()="4294967295"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="contentStringLen"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_4496
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(14)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdtd_4496, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="in_eldecl"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdtd_4496
}

predicate func_3(Variable vdtd_4496, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_4496
}

predicate func_4(Variable vdtd_4496, Variable vnameLen_5375, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="contentStringLen"
		and target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_4496
		and target_4.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vnameLen_5375
}

predicate func_5(Variable vnameLen_5375, ArrayExpr target_5) {
		target_5.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vnameLen_5375
}

from Function func, Variable vdtd_4496, Variable vnameLen_5375, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, ArrayExpr target_5
where
not func_1(vdtd_4496, vnameLen_5375, target_2, target_3, target_4, target_5)
and func_2(vdtd_4496, target_2)
and func_3(vdtd_4496, target_3)
and func_4(vdtd_4496, vnameLen_5375, target_4)
and func_5(vnameLen_5375, target_5)
and vdtd_4496.getType().hasName("DTD *const")
and vnameLen_5375.getType().hasName("int")
and vdtd_4496.getParentScope+() = func
and vnameLen_5375.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
