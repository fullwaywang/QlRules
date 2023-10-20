/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-_reconnectToDB
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/-reconnectToDB
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_backup_archiver.c-_reconnectToDB CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdbname_2981, Variable vqry_2987, FunctionCall target_0) {
		target_0.getTarget().hasName("appendPQExpBuffer")
		and not target_0.getTarget().hasName("initPQExpBuffer")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vqry_2987
		and target_0.getArgument(1).(StringLiteral).getValue()="\\connect %s\n\n"
		and target_0.getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vdbname_2981
		and target_0.getArgument(2).(ConditionalExpr).getThen() instanceof FunctionCall
		and target_0.getArgument(2).(ConditionalExpr).getElse() instanceof StringLiteral
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="%s"
		and not target_1.getValue()="%s\n"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vqry_2987, FunctionCall target_2) {
		target_2.getTarget().hasName("destroyPQExpBuffer")
		and not target_2.getTarget().hasName("appendPsqlMetaConnect")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vqry_2987
}

predicate func_3(Parameter vdbname_2981, Parameter vAH_2981, FunctionCall target_14, ExprStmt target_15, ExprStmt target_16) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vdbname_2981
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPsqlMetaConnect")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_2981
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_2981
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_2981
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="\\connect -\n"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_5(Function func) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_5.getEnclosingFunction() = func)
}

*/
/*predicate func_6(Function func) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func)
}

*/
/*predicate func_7(Function func) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="data"
		and target_7.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_7.getEnclosingFunction() = func)
}

*/
predicate func_8(Parameter vdbname_2981, VariableAccess target_8) {
		target_8.getTarget()=vdbname_2981
}

predicate func_9(Parameter vdbname_2981, VariableAccess target_9) {
		target_9.getTarget()=vdbname_2981
		and target_9.getParent().(FunctionCall).getParent().(ConditionalExpr).getThen() instanceof FunctionCall
}

predicate func_11(Parameter vdbname_2981, FunctionCall target_11) {
		target_11.getTarget().hasName("fmtId")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vdbname_2981
		and target_11.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Variable vqry_2987, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="data"
		and target_13.getQualifier().(VariableAccess).getTarget()=vqry_2987
}

predicate func_14(Parameter vAH_2981, FunctionCall target_14) {
		target_14.getTarget().hasName("RestoringToDB")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vAH_2981
}

predicate func_15(Parameter vdbname_2981, Parameter vAH_2981, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("ReconnectToServer")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_2981
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_2981
		and target_15.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_16(Variable vqry_2987, Parameter vAH_2981, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_2981
		and target_16.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqry_2987
}

from Function func, Parameter vdbname_2981, Variable vqry_2987, Parameter vAH_2981, FunctionCall target_0, StringLiteral target_1, FunctionCall target_2, VariableAccess target_8, VariableAccess target_9, FunctionCall target_11, PointerFieldAccess target_13, FunctionCall target_14, ExprStmt target_15, ExprStmt target_16
where
func_0(vdbname_2981, vqry_2987, target_0)
and func_1(func, target_1)
and func_2(vqry_2987, target_2)
and not func_3(vdbname_2981, vAH_2981, target_14, target_15, target_16)
and func_8(vdbname_2981, target_8)
and func_9(vdbname_2981, target_9)
and func_11(vdbname_2981, target_11)
and func_13(vqry_2987, target_13)
and func_14(vAH_2981, target_14)
and func_15(vdbname_2981, vAH_2981, target_15)
and func_16(vqry_2987, vAH_2981, target_16)
and vdbname_2981.getType().hasName("const char *")
and vqry_2987.getType().hasName("PQExpBuffer")
and vAH_2981.getType().hasName("ArchiveHandle *")
and vdbname_2981.getFunction() = func
and vqry_2987.(LocalVariable).getFunction() = func
and vAH_2981.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
