/**
 * @name imagemagick-fe3066122ef72c82415811d25e9e3fad622c0a99-ReadVIFFImage
 * @id cpp/imagemagick/fe3066122ef72c82415811d25e9e3fad622c0a99/ReadVIFFImage
 * @description imagemagick-fe3066122ef72c82415811d25e9e3fad622c0a99-coders/viff.c-ReadVIFFImage CVE-2019-13133
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstatus_222, EqualityOperation target_4) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vstatus_222
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLValue().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_5, Function func) {
	exists(BreakStmt target_1 |
		target_1.toString() = "break;"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vimage_216, EqualityOperation target_5, AssignExpr target_2) {
		target_2.getLValue().(VariableAccess).getTarget()=vimage_216
		and target_2.getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_216
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getLValue().(VariableAccess).getLocation())
}

predicate func_3(EqualityOperation target_5, Function func, ReturnStmt target_3) {
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vstatus_222, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vstatus_222
}

predicate func_5(Variable vimage_216, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("GetNextImageInList")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_216
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vimage_216, Variable vstatus_222, AssignExpr target_2, ReturnStmt target_3, EqualityOperation target_4, EqualityOperation target_5
where
not func_0(vstatus_222, target_4)
and not func_1(target_5, func)
and func_2(vimage_216, target_5, target_2)
and func_3(target_5, func, target_3)
and func_4(vstatus_222, target_4)
and func_5(vimage_216, target_5)
and vimage_216.getType().hasName("Image *")
and vstatus_222.getType().hasName("MagickBooleanType")
and vimage_216.getParentScope+() = func
and vstatus_222.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
