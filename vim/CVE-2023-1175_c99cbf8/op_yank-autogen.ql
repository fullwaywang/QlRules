/**
 * @name vim-c99cbf8f289bdda5d4a77d7ec415850a520330ba-op_yank
 * @id cpp/vim/c99cbf8f289bdda5d4a77d7ec415850a520330ba/op-yank
 * @description vim-c99cbf8f289bdda5d4a77d7ec415850a520330ba-src/register.c-op_yank CVE-2023-1175
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbd_1138, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="startspaces"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_1138
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="startspaces"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_1138
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vbd_1138, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="startspaces"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_1138
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
}

predicate func_3(Variable vbd_1138, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="startspaces"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_1138
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="inclusive"
}

from Function func, Variable vbd_1138, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vbd_1138, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vbd_1138, target_2)
and func_3(vbd_1138, target_3)
and vbd_1138.getType().hasName("block_def")
and vbd_1138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
