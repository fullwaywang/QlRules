/**
 * @name sqlite3-8428b3b437569338a9d1e10c4cd8154acbe33089-multiSelect
 * @id cpp/sqlite3/8428b3b437569338a9d1e10c4cd8154acbe33089/multiSelect
 * @description sqlite3-8428b3b437569338a9d1e10c4cd8154acbe33089-src/select.c-multiSelect CVE-2019-19926
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpParse_2526, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="nErr"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_2526
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpParse_2526, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("sqlite3VdbeExplainPop")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_2526
}

predicate func_2(Parameter vpParse_2526, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("CollSeq **")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("multiSelectCollSeq")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_2526
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Select *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vpParse_2526, ExprStmt target_1, ExprStmt target_2
where
not func_0(vpParse_2526, target_1, target_2, func)
and func_1(vpParse_2526, target_1)
and func_2(vpParse_2526, target_2)
and vpParse_2526.getType().hasName("Parse *")
and vpParse_2526.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
