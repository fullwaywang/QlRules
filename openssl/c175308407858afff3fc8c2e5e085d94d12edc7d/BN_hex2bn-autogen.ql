import cpp

predicate func_0(Parameter va, Variable vi) {
	exists(LogicalAndExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LEExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vi
		and target_0.getLeftOperand().(LEExpr).getGreaterOperand().(DivExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LEExpr).getGreaterOperand().(DivExpr).getValue()="536870911"
		and target_0.getLeftOperand().(LEExpr).getGreaterOperand().(DivExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getLeftOperand().(LEExpr).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getRightOperand().(BitwiseAndExpr).getType().hasName("int")
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getType().hasName("unsigned short")
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getType().hasName("const unsigned short *")
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getType().hasName("char")
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=va
		and target_0.getRightOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi)
}

predicate func_2(Variable vi) {
	exists(GTExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_2.getLesserOperand().(DivExpr).getType().hasName("int")
		and target_2.getLesserOperand().(DivExpr).getValue()="536870911"
		and target_2.getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_3(Variable vret, Variable vi, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EQExpr).getType().hasName("int")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getType().hasName("BIGNUM *")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getType().hasName("int")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getCondition().(GTExpr).getLesserOperand().(AddExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getType().hasName("BIGNUM *")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(LEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vret
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(EQExpr).getLeftOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_5(Parameter va, Variable vi) {
	exists(BitwiseAndExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLeftOperand().(ArrayExpr).getType().hasName("unsigned short")
		and target_5.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getType().hasName("const unsigned short *")
		and target_5.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_5.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getType().hasName("char")
		and target_5.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=va
		and target_5.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi
		and target_5.getParent().(ForStmt).getStmt() instanceof EmptyStmt)
}

from Function func, Parameter va, Variable vret, Variable vi
where
not func_0(va, vi)
and not func_2(vi)
and not func_3(vret, vi, func)
and func_5(va, vi)
and va.getType().hasName("const char *")
and vret.getType().hasName("BIGNUM *")
and vi.getType().hasName("int")
and va.getParentScope+() = func
and vret.getParentScope+() = func
and vi.getParentScope+() = func
select func, va, vret, vi
