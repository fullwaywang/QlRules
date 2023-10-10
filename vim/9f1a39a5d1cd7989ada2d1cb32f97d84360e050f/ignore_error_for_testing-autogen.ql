/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-ignore_error_for_testing
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/ignore-error-for-testing
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/message.c-ignore_error_for_testing CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter verror_582, Variable vignore_error_list, FunctionCall target_0) {
		target_0.getTarget().hasName("ga_add_string")
		and not target_0.getTarget().hasName("ga_copy_string")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vignore_error_list
		and target_0.getArgument(1).(VariableAccess).getTarget()=verror_582
}

from Function func, Parameter verror_582, Variable vignore_error_list, FunctionCall target_0
where
func_0(verror_582, vignore_error_list, target_0)
and verror_582.getType().hasName("char_u *")
and vignore_error_list.getType().hasName("garray_T")
and verror_582.getParentScope+() = func
and not vignore_error_list.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
