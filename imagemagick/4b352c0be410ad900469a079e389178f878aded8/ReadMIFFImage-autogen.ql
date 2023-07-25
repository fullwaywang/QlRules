/**
 * @name imagemagick-4b352c0be410ad900469a079e389178f878aded8-ReadMIFFImage
 * @id cpp/imagemagick/4b352c0be410ad900469a079e389178f878aded8/ReadMIFFImage
 * @description imagemagick-4b352c0be410ad900469a079e389178f878aded8-coders/miff.c-ReadMIFFImage CVE-2018-14436
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vcolormap_1194, PointerFieldAccess target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcolormap_1194
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcolormap_1194
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
}

predicate func_2(PointerFieldAccess target_3, Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(PointerFieldAccess target_3) {
		target_3.getTarget().getName()="depth"
}

from Function func, Variable vcolormap_1194, ExprStmt target_1, EmptyStmt target_2, PointerFieldAccess target_3
where
func_1(vcolormap_1194, target_3, target_1)
and func_2(target_3, func, target_2)
and func_3(target_3)
and vcolormap_1194.getType().hasName("unsigned char *")
and vcolormap_1194.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
