/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-_connectDB
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/-connectDB
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_backup_db.c-_connectDB CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("initPQExpBuffer")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1))
}

predicate func_2(Variable vnewdb_132, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnewdb_132
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_2)
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Variable vvalues_162, ExprStmt target_9, ExprStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_162
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
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
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_5))
}

predicate func_6(Variable vnewdb_132, Variable vvalues_162, VariableAccess target_6) {
		target_6.getTarget()=vnewdb_132
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_162
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
}

predicate func_7(Variable vnewdb_132, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ahlog")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="connecting to database \"%s\" as user \"%s\"\n"
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnewdb_132
		and target_7.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_8(Variable vnewdb_132, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_8.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Connecting to %s as %s\n"
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnewdb_132
		and target_8.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_9(Variable vvalues_162, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_162
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("char *")
}

predicate func_10(Variable vvalues_162, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_162
		and target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("const char *")
}

from Function func, Variable vnewdb_132, Variable vvalues_162, VariableAccess target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(func)
and not func_1(func)
and not func_2(vnewdb_132, target_7, target_8, func)
and not func_3(vvalues_162, target_9, target_10)
and not func_5(func)
and func_6(vnewdb_132, vvalues_162, target_6)
and func_7(vnewdb_132, target_7)
and func_8(vnewdb_132, target_8)
and func_9(vvalues_162, target_9)
and func_10(vvalues_162, target_10)
and vnewdb_132.getType().hasName("const char *")
and vvalues_162.getType().hasName("const char *[7]")
and vnewdb_132.(LocalVariable).getFunction() = func
and vvalues_162.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
