import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="246"
		and not target_0.getValue()="248"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="251"
		and not target_1.getValue()="253"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="255"
		and not target_2.getValue()="257"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="260"
		and not target_3.getValue()="262"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="274"
		and not target_4.getValue()="272"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Function func) {
	exists(AssignExpr target_6 |
		target_6.getType().hasName("int")
		and target_6.getRValue().(Literal).getValue()="1"
		and target_6.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="1"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="0"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Variable vctx) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("BN_CTX_free")
		and target_11.getType().hasName("void")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vctx)
}

predicate func_12(Variable vprivkey, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(VariableAccess).getTarget()=vprivkey
		and target_12.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ASN1_STRING_clear_free")
		and target_12.getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_12.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprivkey
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_13(Variable vndsa, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("sk_pop_free")
		and target_13.getExpr().(FunctionCall).getType().hasName("void")
		and target_13.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_ASN1_TYPE *")
		and target_13.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_13.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vndsa
		and target_13.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse() instanceof Literal
		and target_13.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getType().hasName("..(*)(..)")
		and target_13.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_13.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_13.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_14(Function func) {
	exists(ReturnStmt target_14 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

from Function func, Variable vprivkey, Variable vctx, Variable vndsa
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and not func_5(func)
and not func_6(func)
and func_9(func)
and func_10(func)
and func_11(vctx)
and func_12(vprivkey, func)
and func_13(vndsa, func)
and func_14(func)
and vprivkey.getType().hasName("ASN1_INTEGER *")
and vctx.getType().hasName("BN_CTX *")
and vndsa.getType().hasName("stack_st_ASN1_TYPE *")
and vprivkey.getParentScope+() = func
and vctx.getParentScope+() = func
and vndsa.getParentScope+() = func
select func, vprivkey, vctx, vndsa
