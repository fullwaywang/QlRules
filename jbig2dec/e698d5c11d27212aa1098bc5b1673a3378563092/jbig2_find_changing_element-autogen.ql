/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_find_changing_element
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-find-changing-element
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_mmr.c-jbig2_find_changing_element CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_3, Function func, UnaryMinusExpr target_0) {
		target_0.getValue()="-1"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_3
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Parameter vx_735, BlockStmt target_3, VariableAccess target_2) {
		target_2.getTarget()=vx_735
		and target_2.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(Parameter vx_735, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_735
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vx_735, UnaryMinusExpr target_0, VariableAccess target_2, BlockStmt target_3
where
func_0(target_3, func, target_0)
and func_2(vx_735, target_3, target_2)
and func_3(vx_735, target_3)
and vx_735.getType().hasName("int")
and vx_735.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
