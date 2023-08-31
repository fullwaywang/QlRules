/**
 * @name postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-vacuum_all_databases
 * @id cpp/postgresql/8e5793ab60bba65ffaa0f2237b39c9580d8972c7/vacuum-all-databases
 * @description postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-src/bin/scripts/vacuumdb.c-vacuum_all_databases CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="override_dbname"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ConnParams *")
		and target_1.getRValue() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="override_dbname"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ConnParams *")
		and target_3.getRValue() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Variable vresult_748, Variable vi_751, FunctionCall target_5) {
		target_5.getTarget().hasName("PQgetvalue")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vresult_748
		and target_5.getArgument(1).(VariableAccess).getTarget()=vi_751
		and target_5.getArgument(2).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vresult_748, Variable vi_751, FunctionCall target_6) {
		target_6.getTarget().hasName("PQgetvalue")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vresult_748
		and target_6.getArgument(1).(VariableAccess).getTarget()=vi_751
		and target_6.getArgument(2).(Literal).getValue()="0"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, VariableAccess target_8) {
		target_8.getTarget()=vmaintenance_db_741
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_741
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_742
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_742
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_743
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
}

/*predicate func_9(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, ExprStmt target_32, ExprStmt target_33, VariableAccess target_9) {
		target_9.getTarget()=vhost_741
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_741
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_742
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_742
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_743
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
		and target_9.getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_10(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, ExprStmt target_32, ExprStmt target_33, VariableAccess target_10) {
		target_10.getTarget()=vport_742
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_741
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_741
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_742
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_743
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_11(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, ExprStmt target_32, ExprStmt target_33, VariableAccess target_11) {
		target_11.getTarget()=vusername_742
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_741
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_741
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_742
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_743
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
/*predicate func_12(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, ExprStmt target_32, ExprStmt target_33, VariableAccess target_12) {
		target_12.getTarget()=vprompt_password_743
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_741
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_741
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_742
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_742
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
predicate func_13(Variable vconnstr_749, Function func, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Variable vconnstr_749, AddressOfExpr target_34, AddressOfExpr target_35, FunctionCall target_14) {
		target_14.getTarget().hasName("resetPQExpBuffer")
		and target_14.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and target_34.getOperand().(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_14.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_35.getOperand().(VariableAccess).getLocation())
}

predicate func_15(Variable vconnstr_749, AddressOfExpr target_36, AddressOfExpr target_37, FunctionCall target_15) {
		target_15.getTarget().hasName("appendPQExpBufferStr")
		and target_15.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and target_15.getArgument(1).(StringLiteral).getValue()="dbname="
		and target_36.getOperand().(VariableAccess).getLocation().isBefore(target_15.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_15.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_37.getOperand().(VariableAccess).getLocation())
}

predicate func_16(Variable vconnstr_749, AddressOfExpr target_35, ValueFieldAccess target_17, FunctionCall target_16) {
		target_16.getTarget().hasName("appendConnStrVal")
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and target_16.getArgument(1) instanceof FunctionCall
		and target_35.getOperand().(VariableAccess).getLocation().isBefore(target_16.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(VariableAccess).getLocation())
}

predicate func_17(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25, ExprStmt target_38, ExprStmt target_33, AddressOfExpr target_37, AddressOfExpr target_39, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="data"
		and target_17.getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(VariableAccess).getLocation())
		and target_17.getQualifier().(VariableAccess).getLocation().isBefore(target_39.getOperand().(VariableAccess).getLocation())
}

/*predicate func_18(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25, ExprStmt target_38, ExprStmt target_33, AddressOfExpr target_37, AddressOfExpr target_39, VariableAccess target_18) {
		target_18.getTarget()=vhost_741
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_18.getLocation())
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_19(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25, ExprStmt target_38, ExprStmt target_33, AddressOfExpr target_37, AddressOfExpr target_39, VariableAccess target_19) {
		target_19.getTarget()=vport_742
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_20(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25, ExprStmt target_38, ExprStmt target_33, AddressOfExpr target_37, AddressOfExpr target_39, VariableAccess target_20) {
		target_20.getTarget()=vusername_742
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_21(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25, ExprStmt target_38, ExprStmt target_33, AddressOfExpr target_37, AddressOfExpr target_39, VariableAccess target_21) {
		target_21.getTarget()=vprompt_password_743
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getOperand().(VariableAccess).getLocation())
}

*/
predicate func_22(Variable vconnstr_749, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("resetPQExpBuffer")
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_23(Variable vconnstr_749, AddressOfExpr target_39, AddressOfExpr target_40, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and target_23.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_39.getOperand().(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_40.getOperand().(VariableAccess).getLocation())
}

predicate func_24(Variable vconnstr_749, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_24.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and target_24.getExpr().(FunctionCall).getArgument(1) instanceof FunctionCall
}

predicate func_25(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_25.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_25.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_25.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_25.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_25.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_25.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_25.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_25.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_25.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_25.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_25.getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
}

/*predicate func_26(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_32, AddressOfExpr target_40, AddressOfExpr target_41, ValueFieldAccess target_26) {
		target_26.getTarget().getName()="data"
		and target_26.getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_40.getOperand().(VariableAccess).getLocation().isBefore(target_26.getQualifier().(VariableAccess).getLocation())
		and target_26.getQualifier().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_27(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_32, AddressOfExpr target_40, AddressOfExpr target_41, VariableAccess target_27) {
		target_27.getTarget()=vhost_741
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_40.getOperand().(VariableAccess).getLocation().isBefore(target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_28(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_32, AddressOfExpr target_40, AddressOfExpr target_41, VariableAccess target_28) {
		target_28.getTarget()=vport_742
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_40.getOperand().(VariableAccess).getLocation().isBefore(target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_29(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_32, AddressOfExpr target_40, AddressOfExpr target_41, VariableAccess target_29) {
		target_29.getTarget()=vusername_742
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_40.getOperand().(VariableAccess).getLocation().isBefore(target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_29.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_30(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vconnstr_749, ExprStmt target_32, AddressOfExpr target_40, AddressOfExpr target_41, VariableAccess target_30) {
		target_30.getTarget()=vprompt_password_743
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_749
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_40.getOperand().(VariableAccess).getLocation().isBefore(target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getOperand().(VariableAccess).getLocation())
}

*/
predicate func_31(Variable vconnstr_749, Function func, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_31.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_749
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_31
}

predicate func_32(Parameter vvacopts_739, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("vacuum_one_database")
		and target_32.getExpr().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvacopts_739
		and target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_32.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_32.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhost_741
		and target_32.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vport_742
		and target_32.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vusername_742
		and target_32.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vprompt_password_743
		and target_32.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vconcurrentCons_744
		and target_32.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vprogname_745
		and target_32.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vecho_745
		and target_32.getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vquiet_745
}

predicate func_33(Parameter vecho_745, Variable vresult_748, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_748
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("executeQuery")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vecho_745
}

predicate func_34(Variable vconnstr_749, AddressOfExpr target_34) {
		target_34.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_35(Variable vconnstr_749, AddressOfExpr target_35) {
		target_35.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_36(Variable vconnstr_749, AddressOfExpr target_36) {
		target_36.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_37(Variable vconnstr_749, AddressOfExpr target_37) {
		target_37.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_38(Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vprogname_745, Parameter vecho_745, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectMaintenanceDatabase")
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaintenance_db_741
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_741
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_742
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_742
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_743
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vprogname_745
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vecho_745
}

predicate func_39(Variable vconnstr_749, AddressOfExpr target_39) {
		target_39.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_40(Variable vconnstr_749, AddressOfExpr target_40) {
		target_40.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

predicate func_41(Variable vconnstr_749, AddressOfExpr target_41) {
		target_41.getOperand().(VariableAccess).getTarget()=vconnstr_749
}

from Function func, Parameter vvacopts_739, Parameter vmaintenance_db_741, Parameter vhost_741, Parameter vport_742, Parameter vusername_742, Parameter vprompt_password_743, Parameter vconcurrentCons_744, Parameter vprogname_745, Parameter vecho_745, Parameter vquiet_745, Variable vresult_748, Variable vconnstr_749, Variable vi_751, FunctionCall target_5, FunctionCall target_6, DeclStmt target_7, VariableAccess target_8, ExprStmt target_13, FunctionCall target_14, FunctionCall target_15, FunctionCall target_16, ValueFieldAccess target_17, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_31, ExprStmt target_32, ExprStmt target_33, AddressOfExpr target_34, AddressOfExpr target_35, AddressOfExpr target_36, AddressOfExpr target_37, ExprStmt target_38, AddressOfExpr target_39, AddressOfExpr target_40, AddressOfExpr target_41
where
not func_1(func)
and not func_3(func)
and func_5(vresult_748, vi_751, target_5)
and func_6(vresult_748, vi_751, target_6)
and func_7(func, target_7)
and func_8(vmaintenance_db_741, vhost_741, vport_742, vusername_742, vprompt_password_743, vprogname_745, vecho_745, target_8)
and func_13(vconnstr_749, func, target_13)
and func_14(vconnstr_749, target_34, target_35, target_14)
and func_15(vconnstr_749, target_36, target_37, target_15)
and func_16(vconnstr_749, target_35, target_17, target_16)
and func_17(vvacopts_739, vhost_741, vport_742, vusername_742, vprompt_password_743, vconcurrentCons_744, vprogname_745, vecho_745, vquiet_745, vconnstr_749, target_25, target_38, target_33, target_37, target_39, target_17)
and func_22(vconnstr_749, target_22)
and func_23(vconnstr_749, target_39, target_40, target_23)
and func_24(vconnstr_749, target_24)
and func_25(vvacopts_739, vhost_741, vport_742, vusername_742, vprompt_password_743, vconcurrentCons_744, vprogname_745, vecho_745, vquiet_745, vconnstr_749, target_25)
and func_31(vconnstr_749, func, target_31)
and func_32(vvacopts_739, vhost_741, vport_742, vusername_742, vprompt_password_743, vconcurrentCons_744, vprogname_745, vecho_745, vquiet_745, target_32)
and func_33(vecho_745, vresult_748, target_33)
and func_34(vconnstr_749, target_34)
and func_35(vconnstr_749, target_35)
and func_36(vconnstr_749, target_36)
and func_37(vconnstr_749, target_37)
and func_38(vmaintenance_db_741, vhost_741, vport_742, vusername_742, vprompt_password_743, vprogname_745, vecho_745, target_38)
and func_39(vconnstr_749, target_39)
and func_40(vconnstr_749, target_40)
and func_41(vconnstr_749, target_41)
and vvacopts_739.getType().hasName("vacuumingOptions *")
and vmaintenance_db_741.getType().hasName("const char *")
and vhost_741.getType().hasName("const char *")
and vport_742.getType().hasName("const char *")
and vusername_742.getType().hasName("const char *")
and vprompt_password_743.getType().hasName("trivalue")
and vconcurrentCons_744.getType().hasName("int")
and vprogname_745.getType().hasName("const char *")
and vecho_745.getType().hasName("bool")
and vquiet_745.getType().hasName("bool")
and vresult_748.getType().hasName("PGresult *")
and vconnstr_749.getType().hasName("PQExpBufferData")
and vi_751.getType().hasName("int")
and vvacopts_739.getFunction() = func
and vmaintenance_db_741.getFunction() = func
and vhost_741.getFunction() = func
and vport_742.getFunction() = func
and vusername_742.getFunction() = func
and vprompt_password_743.getFunction() = func
and vconcurrentCons_744.getFunction() = func
and vprogname_745.getFunction() = func
and vecho_745.getFunction() = func
and vquiet_745.getFunction() = func
and vresult_748.(LocalVariable).getFunction() = func
and vconnstr_749.(LocalVariable).getFunction() = func
and vi_751.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
