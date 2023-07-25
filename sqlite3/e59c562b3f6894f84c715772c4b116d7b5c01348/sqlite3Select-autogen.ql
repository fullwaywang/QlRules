/**
 * @name sqlite3-e59c562b3f6894f84c715772c4b116d7b5c01348-sqlite3Select
 * @id cpp/sqlite3/e59c562b3f6894f84c715772c4b116d7b5c01348/sqlite3Select
 * @description sqlite3-e59c562b3f6894f84c715772c4b116d7b5c01348-src/select.c-sqlite3Select CVE-2019-19244
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_5664, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pWin"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_5664
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_5664, Variable vpEList_5671, Variable vsSort_5678, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_5664
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="9"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		//and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3ExprListCompare")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pOrderBy"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsSort_5678
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpEList_5671
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vp_5664, Variable vpEList_5671, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_5664
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967294"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pGroupBy"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_5664
		//and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3ExprListDup")
		//and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("sqlite3 *")
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpEList_5671
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_3(Parameter vp_5664, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="isTnct"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DistinctCtx")
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_5664
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vp_5664, Variable vpEList_5671, Variable vsSort_5678, LogicalAndExpr target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vp_5664, target_2, target_3, target_1)
and func_1(vp_5664, vpEList_5671, vsSort_5678, target_2, target_1)
and func_2(vp_5664, vpEList_5671, target_2)
and func_3(vp_5664, target_3)
and vp_5664.getType().hasName("Select *")
and vpEList_5671.getType().hasName("ExprList *")
and vsSort_5678.getType().hasName("SortCtx")
and vp_5664.getFunction() = func
and vpEList_5671.(LocalVariable).getFunction() = func
and vsSort_5678.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
