/**
 * @name sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-renameUnmapSelectCb
 * @id cpp/sqlite3/38096961c7cd109110ac21d3ed7dad7e0cb0ae06/renameUnmapSelectCb
 * @description sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-src/alter.c-renameUnmapSelectCb CVE-2019-19645
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_759, IfStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_759
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2097152"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_759, IfStmt target_1) {
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="pEList"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_759
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nExpr"
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(ValueFieldAccess).getTarget().getName()="zName"
}

from Function func, Parameter vp_759, IfStmt target_1
where
not func_0(vp_759, target_1, func)
and func_1(vp_759, target_1)
and vp_759.getType().hasName("Select *")
and vp_759.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
