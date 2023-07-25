/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-addArgumentToVtab
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/addArgumentToVtab
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/vtab.c-addArgumentToVtab CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vdb_376, VariableAccess target_1) {
		target_1.getTarget()=vdb_376
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addModuleArgument")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pNewTable"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("sqlite3DbStrNDup")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_376
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vdb_376, VariableAccess target_1
where
func_1(vdb_376, target_1)
and vdb_376.getType().hasName("sqlite3 *")
and vdb_376.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
