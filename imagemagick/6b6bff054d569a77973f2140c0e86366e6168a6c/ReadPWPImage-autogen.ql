/**
 * @name imagemagick-6b6bff054d569a77973f2140c0e86366e6168a6c-ReadPWPImage
 * @id cpp/imagemagick/6b6bff054d569a77973f2140c0e86366e6168a6c/ReadPWPImage
 * @description imagemagick-6b6bff054d569a77973f2140c0e86366e6168a6c-coders/pwp.c-ReadPWPImage CVE-2018-16643
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_139, EqualityOperation target_3, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_139
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vfile_128, Variable vc_139, FunctionCall target_1) {
		target_1.getTarget().hasName("fputc")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vc_139
		and target_1.getArgument(1).(VariableAccess).getTarget()=vfile_128
}

predicate func_2(Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vc_139, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vc_139
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Variable vfile_128, Variable vc_139, FunctionCall target_1, ExprStmt target_2, EqualityOperation target_3
where
not func_0(vc_139, target_3, target_2)
and func_1(vfile_128, vc_139, target_1)
and func_2(func, target_2)
and func_3(vc_139, target_3)
and vfile_128.getType().hasName("FILE *")
and vc_139.getType().hasName("int")
and vfile_128.getParentScope+() = func
and vc_139.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
