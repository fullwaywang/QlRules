/**
 * @name neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-msg_cache_check
 * @id cpp/neomutt/9bfab35522301794483f8f9ed60820bdec9be59e/msg-cache-check
 * @description neomutt-9bfab35522301794483f8f9ed60820bdec9be59e-pop.c-msg_cache_check CVE-2018-14362
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vid_220, LogicalAndExpr target_2) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cache_id")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vid_220
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vid_220, VariableAccess target_1) {
		target_1.getTarget()=vid_220
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("mutt_bcache_del")
}

predicate func_2(Parameter vid_220, LogicalAndExpr target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("mutt_str_strcmp")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hdrs"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vid_220
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vid_220, VariableAccess target_1, LogicalAndExpr target_2
where
not func_0(vid_220, target_2)
and func_1(vid_220, target_1)
and func_2(vid_220, target_2)
and vid_220.getType().hasName("const char *")
and vid_220.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
