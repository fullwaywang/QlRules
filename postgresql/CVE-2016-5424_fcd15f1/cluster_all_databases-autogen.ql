/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-cluster_all_databases
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/cluster-all-databases
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/scripts/clusterdb.c-cluster_all_databases CVE-2016-5424
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

predicate func_3(Variable vdbname_241, ExprStmt target_8) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_241
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vhost_226, Parameter vport_226, Parameter vusername_227, Parameter vprompt_password_227, Parameter vprogname_228, Parameter vecho_228, Parameter vverbose_225, ExprStmt target_9, ExprStmt target_8, ExprStmt target_10) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_4.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_225
		and target_4.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_226
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_226
		and target_4.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_227
		and target_4.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_227
		and target_4.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_228
		and target_4.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_228
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation()))
}

/*predicate func_5(Function func) {
	exists(ValueFieldAccess target_5 |
		target_5.getTarget().getName()="data"
		and target_5.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vhost_226, Parameter vport_226, Parameter vusername_227, Parameter vprompt_password_227, Parameter vprogname_228, Parameter vecho_228, Variable vdbname_241, Parameter vverbose_225, VariableAccess target_7) {
		target_7.getTarget()=vdbname_241
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_225
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_226
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_226
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_227
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_227
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_228
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_228
}

predicate func_8(Parameter vprogname_228, Variable vdbname_241, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_8.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: clustering database \"%s\"\n"
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprogname_228
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdbname_241
}

predicate func_9(Parameter vhost_226, Parameter vport_226, Parameter vusername_227, Parameter vprompt_password_227, Parameter vprogname_228, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_226
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_226
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_227
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_227
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_228
}

predicate func_10(Parameter vprogname_228, Parameter vecho_228, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("executeQuery")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprogname_228
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vecho_228
}

from Function func, Parameter vhost_226, Parameter vport_226, Parameter vusername_227, Parameter vprompt_password_227, Parameter vprogname_228, Parameter vecho_228, Variable vdbname_241, Parameter vverbose_225, VariableAccess target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(vdbname_241, target_8)
and not func_4(vhost_226, vport_226, vusername_227, vprompt_password_227, vprogname_228, vecho_228, vverbose_225, target_9, target_8, target_10)
and not func_6(func)
and func_7(vhost_226, vport_226, vusername_227, vprompt_password_227, vprogname_228, vecho_228, vdbname_241, vverbose_225, target_7)
and func_8(vprogname_228, vdbname_241, target_8)
and func_9(vhost_226, vport_226, vusername_227, vprompt_password_227, vprogname_228, target_9)
and func_10(vprogname_228, vecho_228, target_10)
and vhost_226.getType().hasName("const char *")
and vport_226.getType().hasName("const char *")
and vusername_227.getType().hasName("const char *")
and vprompt_password_227.getType().hasName("trivalue")
and vprogname_228.getType().hasName("const char *")
and vecho_228.getType().hasName("bool")
and vdbname_241.getType().hasName("char *")
and vverbose_225.getType().hasName("bool")
and vhost_226.getFunction() = func
and vport_226.getFunction() = func
and vusername_227.getFunction() = func
and vprompt_password_227.getFunction() = func
and vprogname_228.getFunction() = func
and vecho_228.getFunction() = func
and vdbname_241.(LocalVariable).getFunction() = func
and vverbose_225.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
