/**
 * @name vim-8e4b76da1d7e987d43ca960dfbc372d1c617466f-fname_match
 * @id cpp/vim/8e4b76da1d7e987d43ca960dfbc372d1c617466f/fname-match
 * @description vim-8e4b76da1d7e987d43ca960dfbc372d1c617466f-src/buffer.c-fname_match CVE-2022-1620
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrmp_2947, FunctionCall target_2, LogicalAndExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="regprog"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2947
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof BlockStmt
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrmp_2947, Parameter vname_2948, Variable vmatch_2951, Variable vp_2952, FunctionCall target_2, BlockStmt target_1) {
		target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_2952
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("home_replace_save")
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_2948
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_2952
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("vim_regexec")
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrmp_2947
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_2952
		and target_1.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_2951
		and target_1.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vname_2948
		and target_1.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_1.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2952
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vrmp_2947, Parameter vname_2948, FunctionCall target_2) {
		target_2.getTarget().hasName("vim_regexec")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vrmp_2947
		and target_2.getArgument(1).(VariableAccess).getTarget()=vname_2948
		and target_2.getArgument(2).(Literal).getValue()="0"
}

predicate func_3(Parameter vrmp_2947, Variable vp_2952, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_2952
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("vim_regexec")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrmp_2947
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_2952
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Parameter vrmp_2947, Parameter vname_2948, Variable vmatch_2951, Variable vp_2952, BlockStmt target_1, FunctionCall target_2, LogicalAndExpr target_3
where
not func_0(vrmp_2947, target_2, target_3)
and func_1(vrmp_2947, vname_2948, vmatch_2951, vp_2952, target_2, target_1)
and func_2(vrmp_2947, vname_2948, target_2)
and func_3(vrmp_2947, vp_2952, target_3)
and vrmp_2947.getType().hasName("regmatch_T *")
and vname_2948.getType().hasName("char_u *")
and vmatch_2951.getType().hasName("char_u *")
and vp_2952.getType().hasName("char_u *")
and vrmp_2947.getParentScope+() = func
and vname_2948.getParentScope+() = func
and vmatch_2951.getParentScope+() = func
and vp_2952.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
