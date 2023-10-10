/**
 * @name git-f6adec4e329ef0e25e14c63b735a5956dc67b8bc-parse_config
 * @id cpp/git/f6adec4e329ef0e25e14c63b735a5956dc67b8bc/parse-config
 * @description git-f6adec4e329ef0e25e14c63b735a5956dc67b8bc-submodule-config.c-parse_config CVE-2018-17456
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_377, Parameter vvar_377, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("looks_like_command_line_option")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_377
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warn_command_line_option")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_377
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_377
		and target_0.getElse() instanceof IfStmt
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvalue_377, Variable vme_379, Variable vsubmodule_380, NotExpr target_2, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="overwrite"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_379
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="url"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_380
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warn_multiple_config")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="treeish_name"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_379
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_380
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="url"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="url"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_380
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="url"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_380
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_377
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vvalue_377, NotExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vvalue_377
}

predicate func_3(Parameter vvalue_377, Variable vsubmodule_380, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="url"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_380
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_377
}

predicate func_4(Parameter vvar_377, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("config_error_nonbool")
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_377
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("const_error")
}

predicate func_5(Parameter vvar_377, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("config_error_nonbool")
		and target_5.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_377
		and target_5.getExpr().(AssignExpr).getRValue().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("const_error")
}

from Function func, Parameter vvalue_377, Variable vme_379, Variable vsubmodule_380, Parameter vvar_377, IfStmt target_1, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vvalue_377, vvar_377, target_2, target_3, target_4, target_5)
and func_1(vvalue_377, vme_379, vsubmodule_380, target_2, target_1)
and func_2(vvalue_377, target_2)
and func_3(vvalue_377, vsubmodule_380, target_3)
and func_4(vvar_377, target_4)
and func_5(vvar_377, target_5)
and vvalue_377.getType().hasName("const char *")
and vme_379.getType().hasName("parse_config_parameter *")
and vsubmodule_380.getType().hasName("submodule *")
and vvar_377.getType().hasName("const char *")
and vvalue_377.getParentScope+() = func
and vme_379.getParentScope+() = func
and vsubmodule_380.getParentScope+() = func
and vvar_377.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
