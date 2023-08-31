/**
 * @name postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-cluster_all_databases
 * @id cpp/postgresql/8e5793ab60bba65ffaa0f2237b39c9580d8972c7/cluster-all-databases
 * @description postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-src/bin/scripts/clusterdb.c-cluster_all_databases CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vdbname_249, ExprStmt target_21) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="override_dbname"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ConnParams *")
		and target_1.getRValue().(VariableAccess).getTarget()=vdbname_249
		and target_21.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vdbname_249, VariableAccess target_3) {
		target_3.getTarget()=vdbname_249
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, VariableAccess target_5) {
		target_5.getTarget()=vmaintenance_db_231
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_232
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_232
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_233
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_233
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
}

/*predicate func_6(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_6) {
		target_6.getTarget()=vhost_232
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_231
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_232
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_233
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_233
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
		and target_6.getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_7(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_7) {
		target_7.getTarget()=vport_232
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_231
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_232
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_233
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_233
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_8(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_8) {
		target_8.getTarget()=vusername_233
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_231
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_232
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_232
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_233
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_9(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_9) {
		target_9.getTarget()=vprompt_password_233
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_231
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_232
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_232
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_233
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
predicate func_10(Variable vconnstr_238, Function func, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_238
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vconnstr_238, FunctionCall target_11) {
		target_11.getTarget().hasName("resetPQExpBuffer")
		and target_11.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_238
}

predicate func_12(Variable vconnstr_238, FunctionCall target_12) {
		target_12.getTarget().hasName("appendPQExpBufferStr")
		and target_12.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_238
		and target_12.getArgument(1).(StringLiteral).getValue()="dbname="
}

predicate func_13(Variable vconnstr_238, Variable vdbname_249, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_238
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_249
}

predicate func_14(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_14.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_14.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_232
		and target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_232
		and target_14.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_233
		and target_14.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_233
		and target_14.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_14.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
}

/*predicate func_15(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="data"
		and target_15.getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_232
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_232
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_233
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_233
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
}

*/
/*predicate func_16(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_16) {
		target_16.getTarget()=vhost_232
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_232
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_233
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_233
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_17(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_17) {
		target_17.getTarget()=vport_232
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_232
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_233
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_233
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_18(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_18) {
		target_18.getTarget()=vusername_233
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_232
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_232
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_233
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_19(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vecho_234, Variable vconnstr_238, Parameter vverbose_231, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_19) {
		target_19.getTarget()=vprompt_password_233
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cluster_one_database")
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_238
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vverbose_231
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_232
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_232
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_233
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_234
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_234
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
predicate func_20(Variable vconnstr_238, Function func, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_20.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_238
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vprogname_234, Variable vdbname_249, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("pg_printf")
		and target_21.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: clustering database \"%s\"\n"
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprogname_234
		and target_21.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdbname_249
}

predicate func_22(Parameter vecho_234, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("executeQuery")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vecho_234
}

predicate func_23(Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_231
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_232
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_232
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_233
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_233
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_234
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_234
}

predicate func_24(Variable vconnstr_238, AddressOfExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vconnstr_238
}

predicate func_25(Variable vconnstr_238, AddressOfExpr target_25) {
		target_25.getOperand().(VariableAccess).getTarget()=vconnstr_238
}

from Function func, Parameter vhost_232, Parameter vport_232, Parameter vusername_233, Parameter vprompt_password_233, Parameter vprogname_234, Parameter vmaintenance_db_231, Parameter vecho_234, Variable vconnstr_238, Variable vdbname_249, Parameter vverbose_231, VariableAccess target_3, DeclStmt target_4, VariableAccess target_5, ExprStmt target_10, FunctionCall target_11, FunctionCall target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, AddressOfExpr target_24, AddressOfExpr target_25
where
not func_1(vdbname_249, target_21)
and func_3(vdbname_249, target_3)
and func_4(func, target_4)
and func_5(vhost_232, vport_232, vusername_233, vprompt_password_233, vprogname_234, vmaintenance_db_231, vecho_234, target_5)
and func_10(vconnstr_238, func, target_10)
and func_11(vconnstr_238, target_11)
and func_12(vconnstr_238, target_12)
and func_13(vconnstr_238, vdbname_249, target_13)
and func_14(vhost_232, vport_232, vusername_233, vprompt_password_233, vprogname_234, vecho_234, vconnstr_238, vverbose_231, target_14)
and func_20(vconnstr_238, func, target_20)
and func_21(vprogname_234, vdbname_249, target_21)
and func_22(vecho_234, target_22)
and func_23(vhost_232, vport_232, vusername_233, vprompt_password_233, vprogname_234, vmaintenance_db_231, vecho_234, target_23)
and func_24(vconnstr_238, target_24)
and func_25(vconnstr_238, target_25)
and vhost_232.getType().hasName("const char *")
and vport_232.getType().hasName("const char *")
and vusername_233.getType().hasName("const char *")
and vprompt_password_233.getType().hasName("trivalue")
and vprogname_234.getType().hasName("const char *")
and vmaintenance_db_231.getType().hasName("const char *")
and vecho_234.getType().hasName("bool")
and vconnstr_238.getType().hasName("PQExpBufferData")
and vdbname_249.getType().hasName("char *")
and vverbose_231.getType().hasName("bool")
and vhost_232.getFunction() = func
and vport_232.getFunction() = func
and vusername_233.getFunction() = func
and vprompt_password_233.getFunction() = func
and vprogname_234.getFunction() = func
and vmaintenance_db_231.getFunction() = func
and vecho_234.getFunction() = func
and vconnstr_238.(LocalVariable).getFunction() = func
and vdbname_249.(LocalVariable).getFunction() = func
and vverbose_231.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
