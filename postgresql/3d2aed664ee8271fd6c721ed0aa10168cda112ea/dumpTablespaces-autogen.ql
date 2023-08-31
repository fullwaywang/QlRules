/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-dumpTablespaces
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/dumpTablespaces
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dumpall.c-dumpTablespaces CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfspcname_1202, LogicalAndExpr target_6, ExprStmt target_7, VariableAccess target_0) {
		target_0.getTarget()=vfspcname_1202
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: could not parse ACL list (%s) for tablespace \"%s\"\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

predicate func_2(Variable vspcoid_1194, Variable vfspcname_1202, ExprStmt target_7, ExprStmt target_8, VariableAccess target_2) {
		target_2.getTarget()=vfspcname_1202
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("buildShSecLabels")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_tablespace"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vspcoid_1194
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="TABLESPACE"
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getLocation())
		and target_2.getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_5(Variable vspcoid_1194, Variable vfspcname_1202, VariableAccess target_5) {
		target_5.getTarget()=vspcoid_1194
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("buildShSecLabels")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_tablespace"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="TABLESPACE"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vfspcname_1202
}

predicate func_6(Variable vfspcname_1202, LogicalAndExpr target_6) {
		target_6.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("buildACLCommands")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfspcname_1202
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="TABLESPACE"
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(6).(StringLiteral).getValue()=""
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
}

predicate func_7(Variable vfspcname_1202, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="COMMENT ON TABLESPACE %s IS "
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfspcname_1202
}

predicate func_8(Variable vfspcname_1202, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfspcname_1202
}

from Function func, Variable vspcoid_1194, Variable vfspcname_1202, VariableAccess target_0, VariableAccess target_2, VariableAccess target_5, LogicalAndExpr target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(vfspcname_1202, target_6, target_7, target_0)
and func_2(vspcoid_1194, vfspcname_1202, target_7, target_8, target_2)
and func_5(vspcoid_1194, vfspcname_1202, target_5)
and func_6(vfspcname_1202, target_6)
and func_7(vfspcname_1202, target_7)
and func_8(vfspcname_1202, target_8)
and vspcoid_1194.getType().hasName("uint32")
and vfspcname_1202.getType().hasName("char *")
and vspcoid_1194.(LocalVariable).getFunction() = func
and vfspcname_1202.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
