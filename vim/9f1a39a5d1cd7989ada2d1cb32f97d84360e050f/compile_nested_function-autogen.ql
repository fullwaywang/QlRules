/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-compile_nested_function
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/compile-nested-function
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/vim9compile.c-compile_nested_function CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vline_to_free_813, VariableAccess target_1) {
		target_1.getTarget()=vline_to_free_813
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("define_function")
}

from Function func, Parameter vline_to_free_813, VariableAccess target_1
where
func_1(vline_to_free_813, target_1)
and vline_to_free_813.getType().hasName("char_u **")
and vline_to_free_813.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
