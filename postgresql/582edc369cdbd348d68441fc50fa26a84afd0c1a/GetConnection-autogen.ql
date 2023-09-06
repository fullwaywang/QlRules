/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-GetConnection
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/GetConnection
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/pg_basebackup/streamutil.c-GetConnection CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmpconn_56, Variable vstderr, Variable vprogname, Variable vdbname, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().getAChild*().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdbname
		and target_0.getCondition().getAChild*().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQexec")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmpconn_56
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false)"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("PQresultStatus")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: could not clear search_path: %s\n"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprogname
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("PQerrorMessage")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQfinish")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmpconn_56
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtmpconn_56, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("PQfinish")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmpconn_56
}

predicate func_2(Variable vtmpconn_56, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQparameterStatus")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmpconn_56
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="integer_datetimes"
}

predicate func_3(Variable vtmpconn_56, Variable vstderr, Variable vprogname, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: could not connect to server: %s"
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprogname
		and target_3.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("PQerrorMessage")
		and target_3.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmpconn_56
}

predicate func_4(Variable vstderr, Variable vprogname, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: could not determine server setting for integer_datetimes\n"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprogname
}

predicate func_5(Variable vdbname, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char **")
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdbname
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(StringLiteral).getValue()="true"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(StringLiteral).getValue()="database"
}

from Function func, Variable vtmpconn_56, Variable vstderr, Variable vprogname, Variable vdbname, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vtmpconn_56, vstderr, vprogname, vdbname, target_1, target_2, target_3, target_4, target_5, func)
and func_1(vtmpconn_56, target_1)
and func_2(vtmpconn_56, target_2)
and func_3(vtmpconn_56, vstderr, vprogname, target_3)
and func_4(vstderr, vprogname, target_4)
and func_5(vdbname, target_5)
and vtmpconn_56.getType().hasName("PGconn *")
and vstderr.getType().hasName("FILE *")
and vprogname.getType().hasName("const char *")
and vdbname.getType().hasName("char *")
and vtmpconn_56.(LocalVariable).getFunction() = func
and not vstderr.getParentScope+() = func
and not vprogname.getParentScope+() = func
and not vdbname.getParentScope+() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
