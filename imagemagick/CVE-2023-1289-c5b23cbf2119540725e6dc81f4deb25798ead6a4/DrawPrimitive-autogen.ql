/**
 * @name imagemagick-c5b23cbf2119540725e6dc81f4deb25798ead6a4-DrawPrimitive
 * @id cpp/imagemagick/c5b23cbf2119540725e6dc81f4deb25798ead6a4/DrawPrimitive
 * @description imagemagick-c5b23cbf2119540725e6dc81f4deb25798ead6a4-MagickCore/draw.c-DrawPrimitive CVE-2023-1289
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdraw_info_5304, FunctionCall target_0) {
		target_0.getTarget().hasName("CloneImageInfo")
		and not target_0.getTarget().hasName("AcquireImageInfo")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="image_info"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdraw_info_5304
}

predicate func_1(Parameter vdraw_info_5304, Variable vclone_info_5577, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="recursion_depth"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_info_5577
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="recursion_depth"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="image_info"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdraw_info_5304
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdraw_info_5304, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="image_info"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdraw_info_5304
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vdraw_info_5304, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("GetFillColor")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdraw_info_5304
}

predicate func_4(Parameter vdraw_info_5304, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdraw_info_5304
		and target_4.getAnOperand().(Literal).getValue()="65535.0"
}

predicate func_5(Variable vclone_info_5577, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclone_info_5577
		and target_5.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Variable vclone_info_5577, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadInlineImage")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclone_info_5577
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="text"
}

from Function func, Parameter vdraw_info_5304, Variable vclone_info_5577, FunctionCall target_0, PointerFieldAccess target_2, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6
where
func_0(vdraw_info_5304, target_0)
and not func_1(vdraw_info_5304, vclone_info_5577, target_3, target_4, target_5, target_6)
and func_2(vdraw_info_5304, target_2)
and func_3(vdraw_info_5304, target_3)
and func_4(vdraw_info_5304, target_4)
and func_5(vclone_info_5577, target_5)
and func_6(vclone_info_5577, target_6)
and vdraw_info_5304.getType().hasName("const DrawInfo *")
and vclone_info_5577.getType().hasName("ImageInfo *")
and vdraw_info_5304.getParentScope+() = func
and vclone_info_5577.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
