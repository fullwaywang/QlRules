/**
 * @name sqlite3-4c6cddcaabb6a5539cd87347e6be96fe8d1d2d37-tableColumnList
 * @id cpp/sqlite3/4c6cddcaabb6a5539cd87347e6be96fe8d1d2d37/tableColumnList
 * @description sqlite3-4c6cddcaabb6a5539cd87347e6be96fe8d1d2d37-src/shell.c-tableColumnList CVE-2017-15286
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vazCol_3767, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vazCol_3767
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vazCol_3767, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vazCol_3767
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3_mprintf")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("sqlite3_column_text")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("sqlite3_stmt *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_2(Variable vazCol_3767, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vazCol_3767
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vazCol_3767, ExprStmt target_1, ExprStmt target_2
where
not func_0(vazCol_3767, target_1, target_2, func)
and func_1(vazCol_3767, target_1)
and func_2(vazCol_3767, target_2)
and vazCol_3767.getType().hasName("char **")
and vazCol_3767.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
