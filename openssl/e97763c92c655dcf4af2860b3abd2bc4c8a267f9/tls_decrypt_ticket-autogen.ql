import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="48"
		and not target_0.getValue()="16"
		and target_0.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(VariableAccess target_4 |
		target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="2"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter veticklen, Function func) {
	exists(LTExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLesserOperand().(VariableAccess).getTarget()=veticklen
		and target_5.getGreaterOperand() instanceof Literal
		and target_5.getEnclosingFunction() = func
		and target_5.getParent().(IfStmt).getThen() instanceof ReturnStmt)
}

from Function func, Parameter veticklen, Variable vmlen, Variable vret, Variable vctx
where
func_0(func)
and func_4(func)
and func_5(veticklen, func)
and veticklen.getType().hasName("int")
and vmlen.getType().hasName("int")
and vret.getType().hasName("int")
and vctx.getType().hasName("EVP_CIPHER_CTX *")
and veticklen.getParentScope+() = func
and vmlen.getParentScope+() = func
and vret.getParentScope+() = func
and vctx.getParentScope+() = func
select func, veticklen, vmlen, vret, vctx
