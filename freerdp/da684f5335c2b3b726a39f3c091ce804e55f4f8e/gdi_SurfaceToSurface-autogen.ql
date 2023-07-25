/**
 * @name freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-gdi_SurfaceToSurface
 * @id cpp/freerdp/da684f5335c2b3b726a39f3c091ce804e55f4f8e/gdi-SurfaceToSurface
 * @description freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-libfreerdp/gdi/gfx.c-gdi_SurfaceToSurface CVE-2020-15103
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrectSrc_1116, Variable vsurfaceSrc_1119, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, LogicalOrExpr target_9, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_rect_valid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrectSrc_1116
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsurfaceDst_1120, LogicalOrExpr target_9, NotExpr target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_rect_valid")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const RECTANGLE_16")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(GotoStmt).getName() ="fail"
		and target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsurfaceToSurface_1110, Variable vindex_1113, Variable vdestPt_1_1117, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="destPts"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceToSurface_1110
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vindex_1113
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdestPt_1_1117
}

predicate func_5(Variable vdestPt_1_1117, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdestPt_1_1117
		and target_5.getExpr().(AssignExpr).getRValue() instanceof AddressOfExpr
}

predicate func_6(Parameter vsurfaceToSurface_1110, Variable vrectSrc_1116, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrectSrc_1116
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rectSrc"
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceToSurface_1110
}

predicate func_7(Variable vrectSrc_1116, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="right"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrectSrc_1116
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="left"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrectSrc_1116
}

predicate func_8(Variable vsurfaceSrc_1119, Variable vsurfaceDst_1120, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsurfaceSrc_1119
}

predicate func_9(Variable vsurfaceSrc_1119, Variable vsurfaceDst_1120, LogicalOrExpr target_9) {
		target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vsurfaceDst_1120
}

predicate func_10(Variable vrectSrc_1116, Variable vdestPt_1_1117, Variable vsurfaceSrc_1119, Variable vsurfaceDst_1120, NotExpr target_10) {
		target_10.getOperand().(FunctionCall).getTarget().hasName("freerdp_image_copy")
		and target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_10.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_10.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="scanline"
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceDst_1120
		and target_10.getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="x"
		and target_10.getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdestPt_1_1117
		and target_10.getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="y"
		and target_10.getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdestPt_1_1117
		and target_10.getOperand().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getOperand().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_10.getOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="format"
		and target_10.getOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_10.getOperand().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="scanline"
		and target_10.getOperand().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurfaceSrc_1119
		and target_10.getOperand().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="left"
		and target_10.getOperand().(FunctionCall).getArgument(10).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrectSrc_1116
		and target_10.getOperand().(FunctionCall).getArgument(11).(PointerFieldAccess).getTarget().getName()="top"
		and target_10.getOperand().(FunctionCall).getArgument(11).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrectSrc_1116
		and target_10.getOperand().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_10.getOperand().(FunctionCall).getArgument(13).(Literal).getValue()="0"
}

from Function func, Parameter vsurfaceToSurface_1110, Variable vindex_1113, Variable vrectSrc_1116, Variable vdestPt_1_1117, Variable vsurfaceSrc_1119, Variable vsurfaceDst_1120, AddressOfExpr target_3, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, LogicalOrExpr target_9, NotExpr target_10
where
not func_0(vrectSrc_1116, vsurfaceSrc_1119, target_6, target_7, target_8, target_9, func)
and not func_2(vsurfaceDst_1120, target_9, target_10)
and func_3(vsurfaceToSurface_1110, vindex_1113, vdestPt_1_1117, target_3)
and func_5(vdestPt_1_1117, target_5)
and func_6(vsurfaceToSurface_1110, vrectSrc_1116, target_6)
and func_7(vrectSrc_1116, target_7)
and func_8(vsurfaceSrc_1119, vsurfaceDst_1120, target_8)
and func_9(vsurfaceSrc_1119, vsurfaceDst_1120, target_9)
and func_10(vrectSrc_1116, vdestPt_1_1117, vsurfaceSrc_1119, vsurfaceDst_1120, target_10)
and vsurfaceToSurface_1110.getType().hasName("const RDPGFX_SURFACE_TO_SURFACE_PDU *")
and vindex_1113.getType().hasName("UINT16")
and vrectSrc_1116.getType().hasName("const RECTANGLE_16 *")
and vdestPt_1_1117.getType().hasName("RDPGFX_POINT16 *")
and vsurfaceSrc_1119.getType().hasName("gdiGfxSurface *")
and vsurfaceDst_1120.getType().hasName("gdiGfxSurface *")
and vsurfaceToSurface_1110.getParentScope+() = func
and vindex_1113.getParentScope+() = func
and vrectSrc_1116.getParentScope+() = func
and vdestPt_1_1117.getParentScope+() = func
and vsurfaceSrc_1119.getParentScope+() = func
and vsurfaceDst_1120.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
