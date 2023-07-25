/**
 * @name sqlite3-1e9c47be1e81e94a67f788c98fd70e8bf70e3746-sqlite3EndTable
 * @id cpp/sqlite3/1e9c47be1e81e94a67f788c98fd70e8bf70e3746/sqlite3EndTable
 * @description sqlite3-1e9c47be1e81e94a67f788c98fd70e8bf70e3746-src/build.c-sqlite3EndTable CVE-2018-8740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpSelect_1859, Parameter vpParse_1855, ValueFieldAccess target_3, LogicalAndExpr target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vpSelect_1859
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorMsg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1855
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=""
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_5.getCondition().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vpParse_1855, ExprStmt target_6, ExprStmt target_7) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sqlite3ErrorMsg")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpParse_1855
		and target_1.getArgument(1).(StringLiteral).getValue()=""
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_3(ValueFieldAccess target_3) {
		target_3.getTarget().getName()="busy"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="init"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sqlite3 *")
}

predicate func_4(Parameter vpSelect_1859, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("Token *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpSelect_1859
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vpSelect_1859, Parameter vpParse_1855, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vpSelect_1859
		and target_5.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nMem"
		and target_5.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_1855
		and target_5.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nMem"
		and target_5.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_1855
}

predicate func_6(Parameter vpParse_1855, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Table *")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="pNewTable"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_1855
}

predicate func_7(Parameter vpParse_1855, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorMsg")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1855
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="AUTOINCREMENT not allowed on WITHOUT ROWID tables"
}

from Function func, Parameter vpSelect_1859, Parameter vpParse_1855, ValueFieldAccess target_3, LogicalAndExpr target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vpSelect_1859, vpParse_1855, target_3, target_4, target_5, target_6, target_7)
and func_3(target_3)
and func_4(vpSelect_1859, target_4)
and func_5(vpSelect_1859, vpParse_1855, target_5)
and func_6(vpParse_1855, target_6)
and func_7(vpParse_1855, target_7)
and vpSelect_1859.getType().hasName("Select *")
and vpParse_1855.getType().hasName("Parse *")
and vpSelect_1859.getFunction() = func
and vpParse_1855.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
