/**
 * @name neomutt-93b8ac558752d09e1c56d4f1bc82631316fa9c82-fetch_uidl
 * @id cpp/neomutt/93b8ac558752d09e1c56d4f1bc82631316fa9c82/fetch-uidl
 * @description neomutt-93b8ac558752d09e1c56d4f1bc82631316fa9c82-pop.c-fetch_uidl CVE-2018-14356
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vline_190, ExprStmt target_1, EqualityOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_190
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vline_190, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_190
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vline_190, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("mutt_str_strcmp")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_190
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_2.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vline_190, ExprStmt target_1, EqualityOperation target_2
where
not func_0(vline_190, target_1, target_2, func)
and func_1(vline_190, target_1)
and func_2(vline_190, target_2)
and vline_190.getType().hasName("char *")
and vline_190.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
