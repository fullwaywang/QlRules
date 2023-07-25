/**
 * @name imagemagick-916d7bbd2c66a286d379dbd94bc6035c8fab937c-ReadOneMNGImage
 * @id cpp/imagemagick/916d7bbd2c66a286d379dbd94bc6035c8fab937c/ReadOneMNGImage
 * @description imagemagick-916d7bbd2c66a286d379dbd94bc6035c8fab937c-coders/png.c-ReadOneMNGImage CVE-2019-19952
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_2, Function func, ReturnStmt target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vmng_info_5317, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmng_info_5317
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("MngInfoFreeStruct")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmng_info_5317
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vmng_info_5317, ReturnStmt target_0, ExprStmt target_1, EqualityOperation target_2
where
func_0(target_2, func, target_0)
and func_1(vmng_info_5317, target_2, target_1)
and func_2(target_2)
and vmng_info_5317.getType().hasName("MngInfo *")
and vmng_info_5317.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
