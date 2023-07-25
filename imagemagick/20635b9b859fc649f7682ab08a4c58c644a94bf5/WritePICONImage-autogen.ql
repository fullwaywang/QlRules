/**
 * @name imagemagick-20635b9b859fc649f7682ab08a4c58c644a94bf5-WritePICONImage
 * @id cpp/imagemagick/20635b9b859fc649f7682ab08a4c58c644a94bf5/WritePICONImage
 * @description imagemagick-20635b9b859fc649f7682ab08a4c58c644a94bf5-coders/xpm.c-WritePICONImage CVE-2017-11540
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_577, ExprStmt target_1, ExprStmt target_2, VariableAccess target_0) {
		target_0.getTarget()=vimage_577
		and target_0.getParent().(FunctionCall).getParent().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Parameter vimage_577, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("WriteBlobString")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_577
}

predicate func_2(Parameter vimage_577, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("WriteBlobString")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_577
}

from Function func, Parameter vimage_577, VariableAccess target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(vimage_577, target_1, target_2, target_0)
and func_1(vimage_577, target_1)
and func_2(vimage_577, target_2)
and vimage_577.getType().hasName("Image *")
and vimage_577.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
