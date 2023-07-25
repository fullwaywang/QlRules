/**
 * @name mosquitto-9097577b49b7fdcf45d30975976dd93808ccc0c4-config__parse_args
 * @id cpp/mosquitto/9097577b49b7fdcf45d30975976dd93808ccc0c4/config--parse-args
 * @description mosquitto-9097577b49b7fdcf45d30975976dd93808ccc0c4-src/conf.c-config__parse_args CVE-2018-20145
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconfig_380, LogicalOrExpr target_1, ExprStmt target_2, ArrayExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="acl_file"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="listeners"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="listener_count"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="acl_file"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(27)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vconfig_380, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="socket_domain"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="password_file"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="psk_file"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="auth_plugin_config_count"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="allow_anonymous"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="security_options"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_2(Parameter vconfig_380, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="use_subject_as_username"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="listeners"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="listener_count"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="use_subject_as_username"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="default_listener"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
}

predicate func_3(Parameter vconfig_380, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="listeners"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_3.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="listener_count"
		and target_3.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_380
		and target_3.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Parameter vconfig_380, LogicalOrExpr target_1, ExprStmt target_2, ArrayExpr target_3
where
not func_0(vconfig_380, target_1, target_2, target_3)
and func_1(vconfig_380, target_1)
and func_2(vconfig_380, target_2)
and func_3(vconfig_380, target_3)
and vconfig_380.getType().hasName("mosquitto__config *")
and vconfig_380.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
