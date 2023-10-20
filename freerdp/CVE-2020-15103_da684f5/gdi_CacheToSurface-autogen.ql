/**
 * @name freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-gdi_CacheToSurface
 * @id cpp/freerdp/da684f5335c2b3b726a39f3c091ce804e55f4f8e/gdi-CacheToSurface
 * @description freerdp-da684f5335c2b3b726a39f3c091ce804e55f4f8e-libfreerdp/gdi/gfx.c-gdi_CacheToSurface CVE-2020-15103
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsurface_1238, LogicalOrExpr target_9, NotExpr target_10) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_rect_valid")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const RECTANGLE_16")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1238
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1238
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="fail"
		and target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vcacheEntry_1239, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="width"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
}

predicate func_5(Variable vcacheEntry_1239, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="height"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
}

predicate func_6(Parameter vcacheToSurface_1233, Variable vindex_1236, Variable vdestPt_1_1237, AddressOfExpr target_6) {
		target_6.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="destPts"
		and target_6.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheToSurface_1233
		and target_6.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vindex_1236
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdestPt_1_1237
}

predicate func_8(Variable vdestPt_1_1237, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdestPt_1_1237
		and target_8.getExpr().(AssignExpr).getRValue() instanceof AddressOfExpr
}

predicate func_9(Variable vsurface_1238, Variable vcacheEntry_1239, LogicalOrExpr target_9) {
		target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vsurface_1238
		and target_9.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vcacheEntry_1239
}

predicate func_10(Variable vdestPt_1_1237, Variable vsurface_1238, Variable vcacheEntry_1239, NotExpr target_10) {
		target_10.getOperand().(FunctionCall).getTarget().hasName("freerdp_image_copy")
		and target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1238
		and target_10.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_10.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1238
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="scanline"
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsurface_1238
		and target_10.getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="x"
		and target_10.getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdestPt_1_1237
		and target_10.getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="y"
		and target_10.getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdestPt_1_1237
		and target_10.getOperand().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="width"
		and target_10.getOperand().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
		and target_10.getOperand().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="height"
		and target_10.getOperand().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
		and target_10.getOperand().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getOperand().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
		and target_10.getOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="format"
		and target_10.getOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
		and target_10.getOperand().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="scanline"
		and target_10.getOperand().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcacheEntry_1239
		and target_10.getOperand().(FunctionCall).getArgument(10).(Literal).getValue()="0"
		and target_10.getOperand().(FunctionCall).getArgument(11).(Literal).getValue()="0"
		and target_10.getOperand().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_10.getOperand().(FunctionCall).getArgument(13).(Literal).getValue()="0"
}

from Function func, Parameter vcacheToSurface_1233, Variable vindex_1236, Variable vdestPt_1_1237, Variable vsurface_1238, Variable vcacheEntry_1239, PointerFieldAccess target_4, PointerFieldAccess target_5, AddressOfExpr target_6, ExprStmt target_8, LogicalOrExpr target_9, NotExpr target_10
where
not func_1(vsurface_1238, target_9, target_10)
and func_4(vcacheEntry_1239, target_4)
and func_5(vcacheEntry_1239, target_5)
and func_6(vcacheToSurface_1233, vindex_1236, vdestPt_1_1237, target_6)
and func_8(vdestPt_1_1237, target_8)
and func_9(vsurface_1238, vcacheEntry_1239, target_9)
and func_10(vdestPt_1_1237, vsurface_1238, vcacheEntry_1239, target_10)
and vcacheToSurface_1233.getType().hasName("const RDPGFX_CACHE_TO_SURFACE_PDU *")
and vindex_1236.getType().hasName("UINT16")
and vdestPt_1_1237.getType().hasName("RDPGFX_POINT16 *")
and vsurface_1238.getType().hasName("gdiGfxSurface *")
and vcacheEntry_1239.getType().hasName("gdiGfxCacheEntry *")
and vcacheToSurface_1233.getParentScope+() = func
and vindex_1236.getParentScope+() = func
and vdestPt_1_1237.getParentScope+() = func
and vsurface_1238.getParentScope+() = func
and vcacheEntry_1239.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
