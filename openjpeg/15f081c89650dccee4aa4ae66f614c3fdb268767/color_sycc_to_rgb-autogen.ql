/**
 * @name openjpeg-15f081c89650dccee4aa4ae66f614c3fdb268767-color_sycc_to_rgb
 * @id cpp/openjpeg/15f081c89650dccee4aa4ae66f614c3fdb268767/color-sycc-to-rgb
 * @description openjpeg-15f081c89650dccee4aa4ae66f614c3fdb268767-src/bin/common/color.c-color_sycc_to_rgb CVE-2016-3183
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="324"
		and not target_0.getValue()="350"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%d:color_sycc_to_rgb\n\tCAN NOT CONVERT\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="/opt/project/build/cloned/openjpeg/src/bin/common/color.c"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vimg_285, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_space"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_285
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Parameter vimg_285, Literal target_0, ExprStmt target_1
where
func_0(func, target_0)
and func_1(vimg_285, func, target_1)
and vimg_285.getType().hasName("opj_image_t *")
and vimg_285.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
