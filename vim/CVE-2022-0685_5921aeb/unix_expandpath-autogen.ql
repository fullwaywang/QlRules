/**
 * @name vim-5921aeb5741fc6e84c870d68c7c35b93ad0c9f87-unix_expandpath
 * @id cpp/vim/5921aeb5741fc6e84c870d68c7c35b93ad0c9f87/unix-expandpath
 * @description vim-5921aeb5741fc6e84c870d68c7c35b93ad0c9f87-src/filepath.c-unix_expandpath CVE-2022-0685
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("vim_isalpha")
		and target_0.getArgument(0) instanceof ConditionalExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vpath_end_3578, Variable vhas_mbyte, Variable vmb_ptr2char, ConditionalExpr target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_1.getThen().(VariableCall).getExpr().(VariableAccess).getTarget()=vmb_ptr2char
		and target_1.getThen().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vpath_end_3578
		and target_1.getElse().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpath_end_3578
		and target_1.getParent().(ArrayExpr).getArrayBase() instanceof PointerDereferenceExpr
}

predicate func_2(Function func, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_2.getLeftOperand().(ArrayExpr).getArrayOffset() instanceof ConditionalExpr
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vpath_end_3578, Variable vhas_mbyte, Variable vmb_ptr2char, ConditionalExpr target_1, BitwiseAndExpr target_2
where
not func_0(func)
and func_1(vpath_end_3578, vhas_mbyte, vmb_ptr2char, target_1)
and func_2(func, target_2)
and vpath_end_3578.getType().hasName("char_u *")
and vhas_mbyte.getType().hasName("int")
and vmb_ptr2char.getType().hasName("..(*)(..)")
and vpath_end_3578.getParentScope+() = func
and not vhas_mbyte.getParentScope+() = func
and not vmb_ptr2char.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
