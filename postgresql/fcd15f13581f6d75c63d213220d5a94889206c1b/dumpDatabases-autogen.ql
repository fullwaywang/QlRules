/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-dumpDatabases
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/dumpDatabases
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_dumpall.c-dumpDatabases CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="\\connect %s\n\n"
		and not target_0.getValue()="%s\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("initPQExpBuffer")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vdbname_1742, ExprStmt target_8, ExprStmt target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPsqlMetaConnect")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_1742
		and target_8.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vOPF, ExprStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vOPF
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_3.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_4(Function func) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vdbname_1742, VariableAccess target_6) {
		target_6.getTarget()=vdbname_1742
		and target_6.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall
}

predicate func_7(Variable vdbname_1742, Variable vOPF, FunctionCall target_7) {
		target_7.getTarget().hasName("fmtId")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vdbname_1742
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vOPF
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_8(Variable vdbname_1742, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_8.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: dumping database \"%s\"...\n"
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_8.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdbname_1742
}

predicate func_9(Variable vdbname_1742, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("runPgDump")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_1742
}

predicate func_10(Variable vOPF, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vOPF
		and target_10.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SET default_transaction_read_only = off;\n\n"
}

from Function func, Variable vdbname_1742, Variable vOPF, StringLiteral target_0, VariableAccess target_6, FunctionCall target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
func_0(func, target_0)
and not func_1(func)
and not func_2(vdbname_1742, target_8, target_9)
and not func_3(vOPF, target_10)
and not func_5(func)
and func_6(vdbname_1742, target_6)
and func_7(vdbname_1742, vOPF, target_7)
and func_8(vdbname_1742, target_8)
and func_9(vdbname_1742, target_9)
and func_10(vOPF, target_10)
and vdbname_1742.getType().hasName("char *")
and vOPF.getType().hasName("FILE *")
and vdbname_1742.(LocalVariable).getFunction() = func
and not vOPF.getParentScope+() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
