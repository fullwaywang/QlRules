/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-get_function_args
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/get-function-args
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/userfunc.c-get_function_args CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vline_to_free_213, VariableAccess target_1) {
		target_1.getTarget()=vline_to_free_213
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("get_function_line")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Parameter vline_to_free_213, VariableAccess target_1
where
func_1(vline_to_free_213, target_1)
and vline_to_free_213.getType().hasName("char_u **")
and vline_to_free_213.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
