/**
 * @name ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-cdj_set_bpp
 * @id cpp/ghostscript/4f73e8b4d578e69a17f452fa60d2130c5faaefd6/cdj-set-bpp
 * @description ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-contrib/gdevdj9.c-cdj_set_bpp CVE-2020-16291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpdev_2108, Parameter vbpp_2108, Variable vci_2110, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_2110
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(Literal).getValue()="8"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vbpp_2108
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_open"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2108
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_closedevice")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_2108
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpdev_2108, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="cmyk"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_2108
		and target_1.getLesserOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vbpp_2108, Variable vci_2110, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dither_colors"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_2110
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="5"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_3(Parameter vbpp_2108, Variable vci_2110, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="depth"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_2110
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbpp_2108
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="8"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vbpp_2108
}

from Function func, Parameter vpdev_2108, Parameter vbpp_2108, Variable vci_2110, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vpdev_2108, vbpp_2108, vci_2110, target_1, target_2, target_3, func)
and func_1(vpdev_2108, target_1)
and func_2(vbpp_2108, vci_2110, target_2)
and func_3(vbpp_2108, vci_2110, target_3)
and vpdev_2108.getType().hasName("gx_device *")
and vbpp_2108.getType().hasName("int")
and vci_2110.getType().hasName("gx_device_color_info *")
and vpdev_2108.getFunction() = func
and vbpp_2108.getFunction() = func
and vci_2110.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
