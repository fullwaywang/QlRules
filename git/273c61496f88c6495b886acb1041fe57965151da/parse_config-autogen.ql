/**
 * @name git-273c61496f88c6495b886acb1041fe57965151da-parse_config
 * @id cpp/git/273c61496f88c6495b886acb1041fe57965151da/parse-config
 * @description git-273c61496f88c6495b886acb1041fe57965151da-submodule-config.c-parse_config CVE-2018-17456
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_383, Parameter vvar_383, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("looks_like_command_line_option")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_383
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warn_command_line_option")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_383
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_383
		and target_0.getElse() instanceof IfStmt
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvalue_383, Variable vme_385, Variable vsubmodule_386, NotExpr target_2, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="overwrite"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_385
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="path"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warn_multiple_config")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="treeish_name"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_385
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="path"
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="path"
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cache_remove_path")
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cache"
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_385
		and target_1.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="path"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="path"
		and target_1.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_1.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_383
		and target_1.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cache_put_path")
		and target_1.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cache"
		and target_1.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vme_385
		and target_1.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsubmodule_386
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vvalue_383, NotExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vvalue_383
}

predicate func_3(Parameter vvalue_383, Variable vsubmodule_386, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="path"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_383
}

predicate func_4(Parameter vvar_383, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("config_error_nonbool")
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_383
		and target_4.getExpr().(AssignExpr).getRValue().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("const_error")
}

predicate func_5(Parameter vvalue_383, Variable vsubmodule_386, Parameter vvar_383, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fetch_recurse"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubmodule_386
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_fetch_recurse")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_383
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_383
}

from Function func, Parameter vvalue_383, Variable vme_385, Variable vsubmodule_386, Parameter vvar_383, IfStmt target_1, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vvalue_383, vvar_383, target_2, target_3, target_4, target_5)
and func_1(vvalue_383, vme_385, vsubmodule_386, target_2, target_1)
and func_2(vvalue_383, target_2)
and func_3(vvalue_383, vsubmodule_386, target_3)
and func_4(vvar_383, target_4)
and func_5(vvalue_383, vsubmodule_386, vvar_383, target_5)
and vvalue_383.getType().hasName("const char *")
and vme_385.getType().hasName("parse_config_parameter *")
and vsubmodule_386.getType().hasName("submodule *")
and vvar_383.getType().hasName("const char *")
and vvalue_383.getParentScope+() = func
and vme_385.getParentScope+() = func
and vsubmodule_386.getParentScope+() = func
and vvar_383.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
