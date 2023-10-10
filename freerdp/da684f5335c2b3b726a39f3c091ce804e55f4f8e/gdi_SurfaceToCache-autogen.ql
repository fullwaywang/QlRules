/**
 * @name freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-gdi_SurfaceToCache
 * @id cpp/freerdp/da684f5335c2b3b726a39f3c091ce804e55f4f8e/gdi-SurfaceToCache
 * @description freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-libfreerdp/gdi/gfx.c-gdi_SurfaceToCache CVE-2020-15103
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrect_1184, Variable vsurface_1185, ExprStmt target_1, ExprStmt target_2, NotExpr target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_rect_valid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrect_1184
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1185
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1185
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrect_1184, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrect_1184
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rectSrc"
}

predicate func_2(Variable vrect_1184, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="right"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_1184
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="left"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_1184
}

predicate func_3(Variable vsurface_1185, NotExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vsurface_1185
}

predicate func_4(Variable vsurface_1185, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="format"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="format"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1185
}

from Function func, Variable vrect_1184, Variable vsurface_1185, ExprStmt target_1, ExprStmt target_2, NotExpr target_3, ExprStmt target_4
where
not func_0(vrect_1184, vsurface_1185, target_1, target_2, target_3, target_4, func)
and func_1(vrect_1184, target_1)
and func_2(vrect_1184, target_2)
and func_3(vsurface_1185, target_3)
and func_4(vsurface_1185, target_4)
and vrect_1184.getType().hasName("const RECTANGLE_16 *")
and vsurface_1185.getType().hasName("gdiGfxSurface *")
and vrect_1184.getParentScope+() = func
and vsurface_1185.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
