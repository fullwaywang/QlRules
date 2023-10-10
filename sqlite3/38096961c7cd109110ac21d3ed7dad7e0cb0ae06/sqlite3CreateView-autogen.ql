/**
 * @name sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-sqlite3CreateView
 * @id cpp/sqlite3/38096961c7cd109110ac21d3ed7dad7e0cb0ae06/sqlite3CreateView
 * @description sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-src/build.c-sqlite3CreateView CVE-2019-19645
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpSelect_2458, FunctionCall target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSelect_2458
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="2097152"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0)
		and target_1.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpSelect_2458, FunctionCall target_1) {
		target_1.getTarget().hasName("sqlite3FixSelect")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("DbFixer")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vpSelect_2458
}

predicate func_2(Parameter vpSelect_2458, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pSelect"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Table *")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpSelect_2458
}

from Function func, Parameter vpSelect_2458, FunctionCall target_1, ExprStmt target_2
where
not func_0(vpSelect_2458, target_1, target_2, func)
and func_1(vpSelect_2458, target_1)
and func_2(vpSelect_2458, target_2)
and vpSelect_2458.getType().hasName("Select *")
and vpSelect_2458.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
