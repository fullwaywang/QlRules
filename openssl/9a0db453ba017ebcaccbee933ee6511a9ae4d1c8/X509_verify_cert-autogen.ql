import cpp

predicate func_0(Parameter vctx) {
	exists(AssignExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLValue().(PointerFieldAccess).getTarget().getName()="last_untrusted"
		and target_0.getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getRValue().(FunctionCall).getTarget().hasName("sk_num")
		and target_0.getRValue().(FunctionCall).getType().hasName("int")
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_X509 *")
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getType().hasName("stack_st_X509 *")
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0")
}

predicate func_1(Parameter vctx) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="last_untrusted"
		and target_1.getType().hasName("int")
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx)
}

predicate func_2(Function func) {
	exists(PostfixDecrExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getOperand() instanceof PointerFieldAccess
		and target_2.getEnclosingFunction() = func)
}

from Function func, Parameter vctx
where
not func_0(vctx)
and func_1(vctx)
and func_2(func)
and vctx.getType().hasName("X509_STORE_CTX *")
and vctx.getParentScope+() = func
select func, vctx
