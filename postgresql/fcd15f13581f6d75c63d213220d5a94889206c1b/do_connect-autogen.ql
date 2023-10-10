/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-do_connect
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/do-connect
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/psql/command.c-do_connect CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vdbname_1780, LogicalAndExpr target_37, ExprStmt target_18) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdbname_1780
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_37.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_4(Function func) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(Function func) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_5.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getRValue().(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(ValueFieldAccess).getTarget().getName()="data"
		and target_6.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(ValueFieldAccess).getTarget().getName()="data"
		and target_7.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_7))
}

predicate func_11(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_11.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="host"
}

predicate func_12(Parameter vhost_1780, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vhost_1780
}

predicate func_13(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_13.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="port"
}

predicate func_14(Parameter vport_1780, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vport_1780
}

predicate func_15(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_15.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="user"
}

predicate func_16(Parameter vuser_1780, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vuser_1780
}

predicate func_17(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_17.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="dbname"
}

predicate func_18(Parameter vdbname_1780, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdbname_1780
}

predicate func_19(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_19.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_19.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="password"
}

predicate func_20(Variable vpassword_1784, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_20.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpassword_1784
}

predicate func_21(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_21.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="fallback_application_name"
}

predicate func_22(Variable vpset, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="progname"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
}

predicate func_23(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_23.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_23.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="client_encoding"
}

predicate func_24(Variable vpset, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="notty"
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("getenv")
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="PGCLIENTENCODING"
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_24.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(StringLiteral).getValue()="auto"
}

predicate func_25(Variable vkeywords_1877, Variable vparamnum_1879, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vkeywords_1877
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vparamnum_1879
		and target_25.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_26(Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalues_1878
		and target_26.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vparamnum_1879
		and target_26.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_27(Variable vn_conn_1783, Variable vkeywords_1877, Variable vvalues_1878, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_conn_1783
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQconnectdbParams")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkeywords_1877
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalues_1878
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_28(Variable vkeywords_1877, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("pg_free")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkeywords_1877
}

predicate func_29(Variable vvalues_1878, ExprStmt target_29) {
		target_29.getExpr().(FunctionCall).getTarget().hasName("pg_free")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalues_1878
}

predicate func_30(Variable vpassword_1784, IfStmt target_30) {
		target_30.getCondition().(VariableAccess).getTarget()=vpassword_1784
		and target_30.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pg_free")
		and target_30.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpassword_1784
}

predicate func_31(Variable vn_conn_1783, IfStmt target_31) {
		target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("PQstatus")
		and target_31.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
}

predicate func_32(Parameter vuser_1780, Variable vpset, Variable vn_conn_1783, Variable vpassword_1784, IfStmt target_32) {
		target_32.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vpassword_1784
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("PQconnectionNeedsPassword")
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="getPassword"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQfinish")
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
		and target_32.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpassword_1784
		and target_32.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("prompt_for_password")
		and target_32.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuser_1780
}

predicate func_33(Variable vo_conn_1782, Variable vpset, Variable vn_conn_1783, IfStmt target_33) {
		target_33.getCondition().(ValueFieldAccess).getTarget().getName()="cur_cmd_interactive"
		and target_33.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vpset
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psql_error")
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("PQerrorMessage")
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vo_conn_1782
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psql_error")
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Previous connection kept\n"
		and target_33.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("psql_error")
		and target_33.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="\\connect: %s"
		and target_33.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("PQerrorMessage")
		and target_33.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
		and target_33.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vo_conn_1782
		and target_33.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQfinish")
		and target_33.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vo_conn_1782
		and target_33.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="db"
		and target_33.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_34(Variable vn_conn_1783, ExprStmt target_34) {
		target_34.getExpr().(FunctionCall).getTarget().hasName("PQfinish")
		and target_34.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vn_conn_1783
}

predicate func_35(Parameter vdbname_1780, Variable vo_conn_1782, FunctionCall target_35) {
		target_35.getTarget().hasName("PQdb")
		and target_35.getArgument(0).(VariableAccess).getTarget()=vo_conn_1782
		and target_35.getParent().(AssignExpr).getRValue() = target_35
		and target_35.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdbname_1780
}

predicate func_36(Function func, ReturnStmt target_36) {
		target_36.getExpr().(Literal).getValue()="0"
		and target_36.getEnclosingFunction() = func
}

predicate func_37(Parameter vdbname_1780, LogicalAndExpr target_37) {
		target_37.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vdbname_1780
		and target_37.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

from Function func, Parameter vdbname_1780, Parameter vuser_1780, Parameter vhost_1780, Parameter vport_1780, Variable vo_conn_1782, Variable vpset, Variable vn_conn_1783, Variable vpassword_1784, Variable vkeywords_1877, Variable vvalues_1878, Variable vparamnum_1879, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, IfStmt target_30, IfStmt target_31, IfStmt target_32, IfStmt target_33, ExprStmt target_34, FunctionCall target_35, ReturnStmt target_36, LogicalAndExpr target_37
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(vdbname_1780, target_37, target_18)
and not func_5(func)
and not func_6(func)
and not func_7(func)
and func_11(vkeywords_1877, vparamnum_1879, target_11)
and func_12(vhost_1780, vvalues_1878, vparamnum_1879, target_12)
and func_13(vkeywords_1877, vparamnum_1879, target_13)
and func_14(vport_1780, vvalues_1878, vparamnum_1879, target_14)
and func_15(vkeywords_1877, vparamnum_1879, target_15)
and func_16(vuser_1780, vvalues_1878, vparamnum_1879, target_16)
and func_17(vkeywords_1877, vparamnum_1879, target_17)
and func_18(vdbname_1780, vvalues_1878, vparamnum_1879, target_18)
and func_19(vkeywords_1877, vparamnum_1879, target_19)
and func_20(vpassword_1784, vvalues_1878, vparamnum_1879, target_20)
and func_21(vkeywords_1877, vparamnum_1879, target_21)
and func_22(vpset, vvalues_1878, vparamnum_1879, target_22)
and func_23(vkeywords_1877, vparamnum_1879, target_23)
and func_24(vpset, vvalues_1878, vparamnum_1879, target_24)
and func_25(vkeywords_1877, vparamnum_1879, target_25)
and func_26(vvalues_1878, vparamnum_1879, target_26)
and func_27(vn_conn_1783, vkeywords_1877, vvalues_1878, target_27)
and func_28(vkeywords_1877, target_28)
and func_29(vvalues_1878, target_29)
and func_30(vpassword_1784, target_30)
and func_31(vn_conn_1783, target_31)
and func_32(vuser_1780, vpset, vn_conn_1783, vpassword_1784, target_32)
and func_33(vo_conn_1782, vpset, vn_conn_1783, target_33)
and func_34(vn_conn_1783, target_34)
and func_35(vdbname_1780, vo_conn_1782, target_35)
and func_36(func, target_36)
and func_37(vdbname_1780, target_37)
and vdbname_1780.getType().hasName("char *")
and vuser_1780.getType().hasName("char *")
and vhost_1780.getType().hasName("char *")
and vport_1780.getType().hasName("char *")
and vo_conn_1782.getType().hasName("PGconn *")
and vpset.getType().hasName("PsqlSettings")
and vn_conn_1783.getType().hasName("PGconn *")
and vpassword_1784.getType().hasName("char *")
and vkeywords_1877.getType().hasName("const char **")
and vvalues_1878.getType().hasName("const char **")
and vparamnum_1879.getType().hasName("int")
and vdbname_1780.getFunction() = func
and vuser_1780.getFunction() = func
and vhost_1780.getFunction() = func
and vport_1780.getFunction() = func
and vo_conn_1782.(LocalVariable).getFunction() = func
and not vpset.getParentScope+() = func
and vn_conn_1783.(LocalVariable).getFunction() = func
and vpassword_1784.(LocalVariable).getFunction() = func
and vkeywords_1877.(LocalVariable).getFunction() = func
and vvalues_1878.(LocalVariable).getFunction() = func
and vparamnum_1879.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
