/**
 * @name sqlite3-3d863b5e4efb2305d64f87a2128289d1c3ce09b6-sqlite3AlterRenameTable
 * @id cpp/sqlite3/3d863b5e4efb2305d64f87a2128289d1c3ce09b6/sqlite3AlterRenameTable
 * @description sqlite3-3d863b5e4efb2305d64f87a2128289d1c3ce09b6-src/alter.c-sqlite3AlterRenameTable CVE-2020-13631
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpTab_99, Variable vzName_100, Variable vdb_101, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_4, NotExpr target_5, LogicalOrExpr target_1, ExprStmt target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("sqlite3IsShadowTableOf")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_101
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpTab_99
		and target_0.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vzName_100
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vzDb_98, Variable vzName_100, Variable vdb_101, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("sqlite3FindTable")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_101
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzName_100
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vzDb_98
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("sqlite3FindIndex")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_101
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzName_100
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vzDb_98
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vzName_100, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorMsg")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="there is already another table or index with this name: %s"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vzName_100
}

predicate func_3(Variable vpTab_99, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3SchemaToIndex")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="db"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pSchema"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpTab_99
}

predicate func_4(Variable vpTab_99, EqualityOperation target_4) {
		target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("isAlterableTable")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpTab_99
}

predicate func_5(Variable vzName_100, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vzName_100
}

predicate func_6(Variable vzName_100, Variable vdb_101, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vzName_100
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3NameFromToken")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_101
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Token *")
}

from Function func, Variable vzDb_98, Variable vpTab_99, Variable vzName_100, Variable vdb_101, LogicalOrExpr target_1, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_4, NotExpr target_5, ExprStmt target_6
where
not func_0(vpTab_99, vzName_100, vdb_101, target_2, target_3, target_4, target_5, target_1, target_6)
and func_1(vzDb_98, vzName_100, vdb_101, target_2, target_1)
and func_2(vzName_100, target_2)
and func_3(vpTab_99, target_3)
and func_4(vpTab_99, target_4)
and func_5(vzName_100, target_5)
and func_6(vzName_100, vdb_101, target_6)
and vzDb_98.getType().hasName("char *")
and vpTab_99.getType().hasName("Table *")
and vzName_100.getType().hasName("char *")
and vdb_101.getType().hasName("sqlite3 *")
and vzDb_98.(LocalVariable).getFunction() = func
and vpTab_99.(LocalVariable).getFunction() = func
and vzName_100.(LocalVariable).getFunction() = func
and vdb_101.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
