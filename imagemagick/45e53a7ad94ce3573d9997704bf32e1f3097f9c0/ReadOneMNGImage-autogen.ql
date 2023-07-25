/**
 * @name imagemagick-45e53a7ad94ce3573d9997704bf32e1f3097f9c0-ReadOneMNGImage
 * @id cpp/imagemagick/45e53a7ad94ce3573d9997704bf32e1f3097f9c0/ReadOneMNGImage
 * @description imagemagick-45e53a7ad94ce3573d9997704bf32e1f3097f9c0-coders/png.c-ReadOneMNGImage CVE-2017-11526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getRValue() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vi_5102, Variable vchunk_5213, PostfixIncrExpr target_4, EqualityOperation target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vchunk_5213
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5102
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vimage_5068, FunctionCall target_3) {
		target_3.getTarget().hasName("ReadBlobByte")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vimage_5068
}

predicate func_4(Variable vi_5102, PostfixIncrExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vi_5102
}

predicate func_5(Variable vchunk_5213, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vchunk_5213
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vchunk_5213, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vchunk_5213
}

from Function func, Variable vimage_5068, Variable vi_5102, Variable vchunk_5213, FunctionCall target_3, PostfixIncrExpr target_4, EqualityOperation target_5, ExprStmt target_6
where
not func_0(func)
and not func_1(vi_5102, vchunk_5213, target_4, target_5, target_6)
and func_3(vimage_5068, target_3)
and func_4(vi_5102, target_4)
and func_5(vchunk_5213, target_5)
and func_6(vchunk_5213, target_6)
and vimage_5068.getType().hasName("Image *")
and vi_5102.getType().hasName("ssize_t")
and vchunk_5213.getType().hasName("unsigned char *")
and vimage_5068.getParentScope+() = func
and vi_5102.getParentScope+() = func
and vchunk_5213.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
