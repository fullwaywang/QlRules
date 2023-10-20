/**
 * @name vim-4875d6ab068f09df88d24d81de40dcd8d56e243d-compile_assign_unlet
 * @id cpp/vim/4875d6ab068f09df88d24d81de40dcd8d56e243d/compile-assign-unlet
 * @description vim-4875d6ab068f09df88d24d81de40dcd8d56e243d-src/vim9compile.c-compile_assign_unlet CVE-2022-2874
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcctx_1904, LogicalAndExpr target_1, EqualityOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx_skip"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcctx_1904
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcctx_1904, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tt_type"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("need_type")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcctx_1904
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vcctx_1904, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("compile_load_lhs")
		and target_2.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcctx_1904
		and target_2.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vcctx_1904, LogicalAndExpr target_1, EqualityOperation target_2
where
not func_0(vcctx_1904, target_1, target_2, func)
and func_1(vcctx_1904, target_1)
and func_2(vcctx_1904, target_2)
and vcctx_1904.getType().hasName("cctx_T *")
and vcctx_1904.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
