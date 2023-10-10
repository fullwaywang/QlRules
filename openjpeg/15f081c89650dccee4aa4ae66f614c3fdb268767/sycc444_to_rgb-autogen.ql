/**
 * @name openjpeg-15f081c89650dccee4aa4ae66f614c3fdb268767-sycc444_to_rgb
 * @id cpp/openjpeg/15f081c89650dccee4aa4ae66f614c3fdb268767/sycc444-to-rgb
 * @description openjpeg-15f081c89650dccee4aa4ae66f614c3fdb268767-src/bin/common/color.c-sycc444_to_rgb CVE-2016-3183
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Parameter vimg_90, ArrayExpr target_11, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_space"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_90
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_4)
		and target_11.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vr_92, VariableAccess target_12, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_92
		and target_5.getParent().(IfStmt).getCondition()=target_12
}

predicate func_6(Variable vg_92, VariableAccess target_13, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_92
		and target_6.getParent().(IfStmt).getCondition()=target_13
}

predicate func_7(Variable vb_92, VariableAccess target_14, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_92
		and target_7.getParent().(IfStmt).getCondition()=target_14
}

predicate func_8(Variable vr_92, Function func, IfStmt target_8) {
		target_8.getCondition().(VariableAccess).getTarget()=vr_92
		and target_8.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable vg_92, Function func, IfStmt target_9) {
		target_9.getCondition().(VariableAccess).getTarget()=vg_92
		and target_9.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vb_92, Function func, IfStmt target_10) {
		target_10.getCondition().(VariableAccess).getTarget()=vb_92
		and target_10.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Parameter vimg_90, ArrayExpr target_11) {
		target_11.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_11.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_90
		and target_11.getArrayOffset().(Literal).getValue()="2"
}

predicate func_12(Variable vr_92, VariableAccess target_12) {
		target_12.getTarget()=vr_92
}

predicate func_13(Variable vg_92, VariableAccess target_13) {
		target_13.getTarget()=vg_92
}

predicate func_14(Variable vb_92, VariableAccess target_14) {
		target_14.getTarget()=vb_92
}

from Function func, Parameter vimg_90, Variable vr_92, Variable vg_92, Variable vb_92, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, IfStmt target_8, IfStmt target_9, IfStmt target_10, ArrayExpr target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14
where
not func_4(vimg_90, target_11, func)
and func_5(vr_92, target_12, target_5)
and func_6(vg_92, target_13, target_6)
and func_7(vb_92, target_14, target_7)
and func_8(vr_92, func, target_8)
and func_9(vg_92, func, target_9)
and func_10(vb_92, func, target_10)
and func_11(vimg_90, target_11)
and func_12(vr_92, target_12)
and func_13(vg_92, target_13)
and func_14(vb_92, target_14)
and vimg_90.getType().hasName("opj_image_t *")
and vr_92.getType().hasName("int *")
and vg_92.getType().hasName("int *")
and vb_92.getType().hasName("int *")
and vimg_90.getParentScope+() = func
and vr_92.getParentScope+() = func
and vg_92.getParentScope+() = func
and vb_92.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
