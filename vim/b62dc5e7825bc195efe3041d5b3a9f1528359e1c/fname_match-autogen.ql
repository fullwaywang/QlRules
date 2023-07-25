/**
 * @name vim-b62dc5e7825bc195efe3041d5b3a9f1528359e1c-fname_match
 * @id cpp/vim/b62dc5e7825bc195efe3041d5b3a9f1528359e1c/fname-match
 * @description vim-b62dc5e7825bc195efe3041d5b3a9f1528359e1c-src/buffer.c-fname_match CVE-2022-1725
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrmp_2947, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="regprog"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2947
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vname_2948, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vname_2948
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vrmp_2947, Parameter vname_2948, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rm_ic"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2947
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("vim_regexec")
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrmp_2947
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_2948
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vname_2948
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="regprog"
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2947
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("home_replace_save")
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("vim_regexec")
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
}

predicate func_3(Parameter vrmp_2947, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rm_ic"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2947
}

from Function func, Parameter vrmp_2947, Parameter vname_2948, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vrmp_2947, target_2, target_3)
and func_1(vname_2948, target_2, target_1)
and func_2(vrmp_2947, vname_2948, target_2)
and func_3(vrmp_2947, target_3)
and vrmp_2947.getType().hasName("regmatch_T *")
and vname_2948.getType().hasName("char_u *")
and vrmp_2947.getParentScope+() = func
and vname_2948.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
