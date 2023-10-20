/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-create_script_for_cluster_analyze
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/create-script-for-cluster-analyze
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_upgrade/check.c-create_script_for_cluster_analyze CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vuser_specification_1_417, FunctionCall target_0) {
		target_0.getTarget().hasName("pg_free")
		and not target_0.getTarget().hasName("initPQExpBuffer")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vuser_specification_1_417
}

predicate func_2(Variable vuser_specification_1_417) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Variable vuser_specification_1_417, ExprStmt target_18) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("appendPQExpBufferStr")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_3.getArgument(1).(StringLiteral).getValue()="-U "
		and target_18.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vuser_specification_1_417, ValueFieldAccess target_19) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("appendShellString")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19)
}

predicate func_5(Variable vuser_specification_1_417, ValueFieldAccess target_19) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferChar")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_5.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19)
}

predicate func_6(Variable vuser_specification_1_417, ExprStmt target_22) {
	exists(ValueFieldAccess target_6 |
		target_6.getTarget().getName()="data"
		and target_6.getQualifier().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_6.getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_7(Variable vuser_specification_1_417, ExprStmt target_22, ExprStmt target_23) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="data"
		and target_7.getQualifier().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_22.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_7.getQualifier().(VariableAccess).getLocation())
		and target_7.getQualifier().(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_8(Variable vuser_specification_1_417, ExprStmt target_23, ExprStmt target_18) {
	exists(ValueFieldAccess target_8 |
		target_8.getTarget().getName()="data"
		and target_8.getQualifier().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_23.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_8.getQualifier().(VariableAccess).getLocation())
		and target_8.getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_9(Variable vuser_specification_1_417, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vuser_specification_1_417
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_9))
}

predicate func_10(Variable vos_info, ValueFieldAccess target_10) {
		target_10.getTarget().getName()="user"
		and target_10.getQualifier().(VariableAccess).getTarget()=vos_info
}

predicate func_12(Variable vuser_specification_1_417, AssignExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget()=vuser_specification_1_417
		and target_12.getRValue().(FunctionCall).getTarget().hasName("psprintf")
		and target_12.getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="-U \"%s\" "
		and target_12.getRValue().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
}

predicate func_13(Variable vuser_specification_1_417, VariableAccess target_13) {
		target_13.getTarget()=vuser_specification_1_417
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="echo %s    \"%s/vacuumdb\" %s--all %s%s\n"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="'"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="major_version"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="100"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="804"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="--analyze-only"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="--analyze"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="'"
}

predicate func_14(Variable vuser_specification_1_417, VariableAccess target_14) {
		target_14.getTarget()=vuser_specification_1_417
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\"%s/vacuumdb\" %s--all --analyze-in-stages\n"
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
}

predicate func_15(Variable vuser_specification_1_417, VariableAccess target_15) {
		target_15.getTarget()=vuser_specification_1_417
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\"%s/vacuumdb\" %s--all\n"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
}

predicate func_16(Variable vos_info, Function func, IfStmt target_16) {
		target_16.getCondition().(ValueFieldAccess).getTarget().getName()="user_specified"
		and target_16.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vos_info
		and target_16.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_18(Variable vuser_specification_1_417, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_18.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\"%s/vacuumdb\" %s--all\n"
		and target_18.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_18.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_18.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuser_specification_1_417
}

predicate func_19(Variable vos_info, ValueFieldAccess target_19) {
		target_19.getTarget().getName()="user_specified"
		and target_19.getQualifier().(VariableAccess).getTarget()=vos_info
}

predicate func_22(Variable vuser_specification_1_417, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_22.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="echo %s    \"%s/vacuumdb\" %s--all %s%s\n"
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="'"
		and target_22.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_22.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_22.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vuser_specification_1_417
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="major_version"
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="100"
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="804"
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="--analyze-only"
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="--analyze"
		and target_22.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="'"
}

predicate func_23(Variable vuser_specification_1_417, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_23.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\"%s/vacuumdb\" %s--all --analyze-in-stages\n"
		and target_23.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_23.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ClusterInfo")
		and target_23.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuser_specification_1_417
}

from Function func, Variable vuser_specification_1_417, Variable vos_info, FunctionCall target_0, ValueFieldAccess target_10, AssignExpr target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, IfStmt target_16, ExprStmt target_18, ValueFieldAccess target_19, ExprStmt target_22, ExprStmt target_23
where
func_0(vuser_specification_1_417, target_0)
and not func_2(vuser_specification_1_417)
and not func_3(vuser_specification_1_417, target_18)
and not func_4(vuser_specification_1_417, target_19)
and not func_5(vuser_specification_1_417, target_19)
and not func_6(vuser_specification_1_417, target_22)
and not func_7(vuser_specification_1_417, target_22, target_23)
and not func_8(vuser_specification_1_417, target_23, target_18)
and not func_9(vuser_specification_1_417, func)
and func_10(vos_info, target_10)
and func_12(vuser_specification_1_417, target_12)
and func_13(vuser_specification_1_417, target_13)
and func_14(vuser_specification_1_417, target_14)
and func_15(vuser_specification_1_417, target_15)
and func_16(vos_info, func, target_16)
and func_18(vuser_specification_1_417, target_18)
and func_19(vos_info, target_19)
and func_22(vuser_specification_1_417, target_22)
and func_23(vuser_specification_1_417, target_23)
and vuser_specification_1_417.getType().hasName("char *")
and vos_info.getType().hasName("OSInfo")
and vuser_specification_1_417.(LocalVariable).getFunction() = func
and not vos_info.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
