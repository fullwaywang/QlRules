/**
 * @name postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-index_concurrently_build
 * @id cpp/postgresql/a117cebd638dd02e5c2e791c25e43745f233111b/index-concurrently-build
 * @description postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-src/backend/catalog/index.c-index_concurrently_build CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vheapRel_1447, ExprStmt target_5, ExprStmt target_6, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRel_1447
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1)
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_3))
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_4))
}

predicate func_5(Variable vheapRel_1447, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_1447
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
}

predicate func_6(Variable vheapRel_1447, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("index_build")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheapRel_1447
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("IndexInfo *")
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1"
}

from Function func, Variable vheapRel_1447, ExprStmt target_5, ExprStmt target_6
where
not func_0(func)
and not func_1(vheapRel_1447, target_5, target_6, func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and func_5(vheapRel_1447, target_5)
and func_6(vheapRel_1447, target_6)
and vheapRel_1447.getType().hasName("Relation")
and vheapRel_1447.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
