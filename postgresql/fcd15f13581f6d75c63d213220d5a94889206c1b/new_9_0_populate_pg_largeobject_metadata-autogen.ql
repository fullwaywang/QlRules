/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-new_9_0_populate_pg_largeobject_metadata
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/new-9-0-populate-pg-largeobject-metadata
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_upgrade/version.c-new_9_0_populate_pg_largeobject_metadata CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vscript_25, Variable vactive_db_37, FunctionCall target_0) {
		target_0.getTarget().hasName("fprintf")
		and not target_0.getTarget().hasName("fputs")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vscript_25
		and target_0.getArgument(1).(StringLiteral).getValue()="\\connect %s\n"
		and target_0.getArgument(2).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_0.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="db_name"
		and target_0.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vactive_db_37
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("initPQExpBuffer")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vactive_db_37, NotExpr target_7, FunctionCall target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPsqlMetaConnect")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db_name"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vactive_db_37
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vscript_25, NotExpr target_7, LogicalAndExpr target_9, ExprStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("fputs")
		and target_3.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscript_25
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_4(Function func) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(NotExpr target_7, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vactive_db_37, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="db_name"
		and target_6.getQualifier().(VariableAccess).getTarget()=vactive_db_37
		and target_6.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("quote_identifier")
}

predicate func_7(NotExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_8(Variable vactive_db_37, FunctionCall target_8) {
		target_8.getTarget().hasName("connectToServer")
		and target_8.getArgument(0).(VariableAccess).getTarget().getType().hasName("ClusterInfo *")
		and target_8.getArgument(1).(PointerFieldAccess).getTarget().getName()="db_name"
		and target_8.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vactive_db_37
}

predicate func_9(Variable vscript_25, LogicalAndExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vscript_25
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vscript_25
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fopen_priv")
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char[1024]")
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="w"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vscript_25, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vscript_25
		and target_10.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.lo_create(t.loid)\nFROM (SELECT DISTINCT loid FROM pg_catalog.pg_largeobject) AS t;\n"
}

from Function func, Variable vscript_25, Variable vactive_db_37, FunctionCall target_0, PointerFieldAccess target_6, NotExpr target_7, FunctionCall target_8, LogicalAndExpr target_9, ExprStmt target_10
where
func_0(vscript_25, vactive_db_37, target_0)
and not func_1(func)
and not func_2(vactive_db_37, target_7, target_8)
and not func_3(vscript_25, target_7, target_9, target_10)
and not func_5(target_7, func)
and func_6(vactive_db_37, target_6)
and func_7(target_7)
and func_8(vactive_db_37, target_8)
and func_9(vscript_25, target_9)
and func_10(vscript_25, target_10)
and vscript_25.getType().hasName("FILE *")
and vactive_db_37.getType().hasName("DbInfo *")
and vscript_25.(LocalVariable).getFunction() = func
and vactive_db_37.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
