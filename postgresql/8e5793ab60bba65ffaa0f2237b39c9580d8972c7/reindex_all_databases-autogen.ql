/**
 * @name postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-reindex_all_databases
 * @id cpp/postgresql/8e5793ab60bba65ffaa0f2237b39c9580d8972c7/reindex-all-databases
 * @description postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-src/bin/scripts/reindexdb.c-reindex_all_databases CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vdbname_727, ExprStmt target_21) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="override_dbname"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ConnParams *")
		and target_1.getRValue().(VariableAccess).getTarget()=vdbname_727
		and target_21.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vdbname_727, VariableAccess target_3) {
		target_3.getTarget()=vdbname_727
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, VariableAccess target_5) {
		target_5.getTarget()=vmaintenance_db_708
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_709
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_709
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_710
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_710
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
}

/*predicate func_6(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_6) {
		target_6.getTarget()=vhost_709
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_708
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_709
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_710
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_710
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_7(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_7) {
		target_7.getTarget()=vport_709
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_708
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_709
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_710
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_710
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
		and target_7.getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_8(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_8) {
		target_8.getTarget()=vusername_710
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_708
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_709
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_709
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_710
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_9(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, ExprStmt target_14, ExprStmt target_21, ExprStmt target_22, VariableAccess target_9) {
		target_9.getTarget()=vprompt_password_710
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_708
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_709
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_709
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_710
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
predicate func_10(Variable vconnstr_716, Function func, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_716
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vconnstr_716, FunctionCall target_11) {
		target_11.getTarget().hasName("resetPQExpBuffer")
		and target_11.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_716
}

predicate func_12(Variable vconnstr_716, FunctionCall target_12) {
		target_12.getTarget().hasName("appendPQExpBufferStr")
		and target_12.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_716
		and target_12.getArgument(1).(StringLiteral).getValue()="dbname="
}

predicate func_13(Variable vconnstr_716, Variable vdbname_727, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_716
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdbname_727
}

predicate func_14(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_14.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_14.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_709
		and target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_709
		and target_14.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_710
		and target_14.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_710
		and target_14.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_14.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_14.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_14.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_14.getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
}

/*predicate func_15(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="data"
		and target_15.getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_709
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_709
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_710
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_710
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
}

*/
/*predicate func_16(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_16) {
		target_16.getTarget()=vhost_709
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_709
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_710
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_710
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_17(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_17) {
		target_17.getTarget()=vport_709
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_709
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_710
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_710
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_17.getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_18(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_18) {
		target_18.getTarget()=vusername_710
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_709
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_709
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vprompt_password_710
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_19(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, ExprStmt target_23, ExprStmt target_21, ExprStmt target_22, AddressOfExpr target_24, AddressOfExpr target_25, VariableAccess target_19) {
		target_19.getTarget()=vprompt_password_710
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reindex_one_database")
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_716
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhost_709
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vport_709
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vusername_710
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprogname_711
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vecho_711
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vverbose_711
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vconcurrently_712
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vconcurrentCons_712
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(VariableAccess).getLocation())
}

*/
predicate func_20(Variable vconnstr_716, Function func, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_20.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_716
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vprogname_711, Variable vdbname_727, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("pg_printf")
		and target_21.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: reindexing database \"%s\"\n"
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprogname_711
		and target_21.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdbname_727
}

predicate func_22(Parameter vecho_711, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("executeQuery")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vecho_711
}

predicate func_23(Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vmaintenance_db_708, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_708
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_709
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_709
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_710
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_710
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_711
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_711
}

predicate func_24(Variable vconnstr_716, AddressOfExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vconnstr_716
}

predicate func_25(Variable vconnstr_716, AddressOfExpr target_25) {
		target_25.getOperand().(VariableAccess).getTarget()=vconnstr_716
}

from Function func, Parameter vport_709, Parameter vusername_710, Parameter vprompt_password_710, Parameter vprogname_711, Parameter vhost_709, Parameter vecho_711, Parameter vverbose_711, Parameter vconcurrently_712, Parameter vconcurrentCons_712, Variable vconnstr_716, Variable vdbname_727, Parameter vmaintenance_db_708, VariableAccess target_3, DeclStmt target_4, VariableAccess target_5, ExprStmt target_10, FunctionCall target_11, FunctionCall target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, AddressOfExpr target_24, AddressOfExpr target_25
where
not func_1(vdbname_727, target_21)
and func_3(vdbname_727, target_3)
and func_4(func, target_4)
and func_5(vport_709, vusername_710, vprompt_password_710, vprogname_711, vhost_709, vecho_711, vmaintenance_db_708, target_5)
and func_10(vconnstr_716, func, target_10)
and func_11(vconnstr_716, target_11)
and func_12(vconnstr_716, target_12)
and func_13(vconnstr_716, vdbname_727, target_13)
and func_14(vport_709, vusername_710, vprompt_password_710, vprogname_711, vhost_709, vecho_711, vverbose_711, vconcurrently_712, vconcurrentCons_712, vconnstr_716, target_14)
and func_20(vconnstr_716, func, target_20)
and func_21(vprogname_711, vdbname_727, target_21)
and func_22(vecho_711, target_22)
and func_23(vport_709, vusername_710, vprompt_password_710, vprogname_711, vhost_709, vecho_711, vmaintenance_db_708, target_23)
and func_24(vconnstr_716, target_24)
and func_25(vconnstr_716, target_25)
and vport_709.getType().hasName("const char *")
and vusername_710.getType().hasName("const char *")
and vprompt_password_710.getType().hasName("trivalue")
and vprogname_711.getType().hasName("const char *")
and vhost_709.getType().hasName("const char *")
and vecho_711.getType().hasName("bool")
and vverbose_711.getType().hasName("bool")
and vconcurrently_712.getType().hasName("bool")
and vconcurrentCons_712.getType().hasName("int")
and vconnstr_716.getType().hasName("PQExpBufferData")
and vdbname_727.getType().hasName("char *")
and vmaintenance_db_708.getType().hasName("const char *")
and vport_709.getFunction() = func
and vusername_710.getFunction() = func
and vprompt_password_710.getFunction() = func
and vprogname_711.getFunction() = func
and vhost_709.getFunction() = func
and vecho_711.getFunction() = func
and vverbose_711.getFunction() = func
and vconcurrently_712.getFunction() = func
and vconcurrentCons_712.getFunction() = func
and vconnstr_716.(LocalVariable).getFunction() = func
and vdbname_727.(LocalVariable).getFunction() = func
and vmaintenance_db_708.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
