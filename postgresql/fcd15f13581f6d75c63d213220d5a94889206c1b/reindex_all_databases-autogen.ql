/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-reindex_all_databases
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/reindex-all-databases
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/scripts/reindexdb.c-reindex_all_databases CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("resetPQExpBuffer")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vdbname_343, ExprStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_343
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, Parameter vecho_330, Parameter vverbose_330, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_4.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="DATABASE"
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_328
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_328
		and target_4.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_329
		and target_4.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_329
		and target_4.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_330
		and target_4.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_330
		and target_4.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_330
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation()))
}

/*predicate func_6(Function func) {
	exists(ValueFieldAccess target_6 |
		target_6.getTarget().getName()="data"
		and target_6.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_7))
}

predicate func_8(Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, Parameter vecho_330, Parameter vverbose_330, Variable vdbname_343, VariableAccess target_8) {
		target_8.getTarget()=vdbname_343
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_343
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="DATABASE"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_328
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_328
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_329
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_329
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_330
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_330
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_330
}

predicate func_9(Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, Parameter vecho_330, Parameter vverbose_330, Variable vdbname_343, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, VariableAccess target_9) {
		target_9.getTarget()=vdbname_343
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_343
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="DATABASE"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_328
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_328
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_329
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_329
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_330
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_330
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_330
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
}

predicate func_10(Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, Parameter vecho_330, Parameter vverbose_330, Variable vdbname_343, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_343
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_343
		and target_10.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="DATABASE"
		and target_10.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_328
		and target_10.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_328
		and target_10.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_329
		and target_10.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_329
		and target_10.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_330
		and target_10.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_330
		and target_10.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_330
}

predicate func_11(Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_328
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_328
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_329
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_329
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_330
}

predicate func_12(Parameter vprogname_330, Variable vdbname_343, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_12.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: reindexing database \"%s\"\n"
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprogname_330
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdbname_343
}

predicate func_13(Parameter vprogname_330, Parameter vecho_330, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("executeQuery")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprogname_330
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vecho_330
}

from Function func, Parameter vhost_328, Parameter vport_328, Parameter vusername_329, Parameter vprompt_password_329, Parameter vprogname_330, Parameter vecho_330, Parameter vverbose_330, Variable vdbname_343, VariableAccess target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(vdbname_343, target_10)
and not func_4(vhost_328, vport_328, vusername_329, vprompt_password_329, vprogname_330, vecho_330, vverbose_330, target_11, target_12, target_13)
and not func_7(func)
and func_8(vhost_328, vport_328, vusername_329, vprompt_password_329, vprogname_330, vecho_330, vverbose_330, vdbname_343, target_8)
and func_9(vhost_328, vport_328, vusername_329, vprompt_password_329, vprogname_330, vecho_330, vverbose_330, vdbname_343, target_11, target_12, target_13, target_9)
and func_10(vhost_328, vport_328, vusername_329, vprompt_password_329, vprogname_330, vecho_330, vverbose_330, vdbname_343, target_10)
and func_11(vhost_328, vport_328, vusername_329, vprompt_password_329, vprogname_330, target_11)
and func_12(vprogname_330, vdbname_343, target_12)
and func_13(vprogname_330, vecho_330, target_13)
and vhost_328.getType().hasName("const char *")
and vport_328.getType().hasName("const char *")
and vusername_329.getType().hasName("const char *")
and vprompt_password_329.getType().hasName("trivalue")
and vprogname_330.getType().hasName("const char *")
and vecho_330.getType().hasName("bool")
and vverbose_330.getType().hasName("bool")
and vdbname_343.getType().hasName("char *")
and vhost_328.getFunction() = func
and vport_328.getFunction() = func
and vusername_329.getFunction() = func
and vprompt_password_329.getFunction() = func
and vprogname_330.getFunction() = func
and vecho_330.getFunction() = func
and vverbose_330.getFunction() = func
and vdbname_343.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
