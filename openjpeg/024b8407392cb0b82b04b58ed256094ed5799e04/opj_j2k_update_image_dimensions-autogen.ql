/**
 * @name openjpeg-024b8407392cb0b82b04b58ed256094ed5799e04-opj_j2k_update_image_dimensions
 * @id cpp/openjpeg/024b8407392cb0b82b04b58ed256094ed5799e04/opj-j2k-update-image-dimensions
 * @description openjpeg-024b8407392cb0b82b04b58ed256094ed5799e04-src/lib/openjp2/j2k.c-opj_j2k_update_image_dimensions CVE-2020-6851
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_image_9214, Parameter vp_manager_9215, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="x0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="x1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_9215
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Image coordinates above INT_MAX are not supported\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_image_9214, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
}

predicate func_2(Parameter vp_image_9214, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="x0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_int_ceildiv")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="x0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_9214
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dx"
}

predicate func_3(Parameter vp_manager_9215, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_9215
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Size x of the decoded component image is incorrect (comp[%d].w=%d).\n"
}

from Function func, Parameter vp_image_9214, Parameter vp_manager_9215, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vp_image_9214, vp_manager_9215, target_1, target_2, target_3)
and func_1(vp_image_9214, target_1)
and func_2(vp_image_9214, target_2)
and func_3(vp_manager_9215, target_3)
and vp_image_9214.getType().hasName("opj_image_t *")
and vp_manager_9215.getType().hasName("opj_event_mgr_t *")
and vp_image_9214.getParentScope+() = func
and vp_manager_9215.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
