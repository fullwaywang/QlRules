/**
 * @name vim-1889f499a4f248cd84e0e0bf6d0d820016774494-compile_nested_function
 * @id cpp/vim/1889f499a4f248cd84e0e0bf6d0d820016774494/compile-nested-function
 * @description vim-1889f499a4f248cd84e0e0bf6d0d820016774494-src/vim9compile.c-compile_nested_function CVE-2022-2862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vlvar_939, VariableAccess target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlvar_939
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4)
}

predicate func_2(LogicalAndExpr target_5, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("lvar_T *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lv_name"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("lvar_T *")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="47"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vcctx_821, Variable vname_start_824, Variable vname_end_825, Variable vfunc_name_827, Variable vufunc_829, FunctionCall target_3) {
		target_3.getTarget().hasName("reserve_local")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vcctx_821
		and target_3.getArgument(1).(VariableAccess).getTarget()=vfunc_name_827
		and target_3.getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vname_end_825
		and target_3.getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vname_start_824
		and target_3.getArgument(3).(Literal).getValue()="1"
		and target_3.getArgument(4).(PointerFieldAccess).getTarget().getName()="uf_func_type"
		and target_3.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vufunc_829
}

predicate func_4(Variable vis_global_823, VariableAccess target_4) {
		target_4.getTarget()=vis_global_823
}

predicate func_5(Parameter vcctx_821, Variable vufunc_829, LogicalAndExpr target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("func_needs_compiling")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vufunc_829
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("compile_def_function")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vufunc_829
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcctx_821
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vcctx_821, Variable vis_global_823, Variable vname_start_824, Variable vname_end_825, Variable vfunc_name_827, Variable vufunc_829, Variable vlvar_939, FunctionCall target_3, VariableAccess target_4, LogicalAndExpr target_5
where
not func_1(vlvar_939, target_4)
and not func_2(target_5, func)
and func_3(vcctx_821, vname_start_824, vname_end_825, vfunc_name_827, vufunc_829, target_3)
and func_4(vis_global_823, target_4)
and func_5(vcctx_821, vufunc_829, target_5)
and vcctx_821.getType().hasName("cctx_T *")
and vis_global_823.getType().hasName("int")
and vname_start_824.getType().hasName("char_u *")
and vname_end_825.getType().hasName("char_u *")
and vfunc_name_827.getType().hasName("char_u *")
and vufunc_829.getType().hasName("ufunc_T *")
and vlvar_939.getType().hasName("lvar_T *")
and vcctx_821.getParentScope+() = func
and vis_global_823.getParentScope+() = func
and vname_start_824.getParentScope+() = func
and vname_end_825.getParentScope+() = func
and vfunc_name_827.getParentScope+() = func
and vufunc_829.getParentScope+() = func
and vlvar_939.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
