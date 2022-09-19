import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="721"
		and not target_0.getValue()="732"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="727"
		and not target_1.getValue()="738"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vprio, Variable vz) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("const SSL_CIPHER *")
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("sk_value")
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getType().hasName("void *")
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vz)
}

predicate func_3(Variable vprio, Variable vallow, Variable vz) {
	exists(LogicalOrExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_3.getLeftOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_3.getLeftOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_ssl"
		and target_3.getLeftOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned long")
		and target_3.getLeftOperand().(EQExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_3.getRightOperand().(LTExpr).getType().hasName("int")
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_SSL_CIPHER *")
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getType().hasName("const SSL_CIPHER *")
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sk_delete")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vz
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vz)
}

predicate func_5(Parameter vs) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EQExpr).getType().hasName("int")
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("sk_num")
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_SSL_CIPHER *")
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_5.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_5.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="106"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="185"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s2_srvr.c"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="713"
		and target_5.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_5.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_5.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hit"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_7(Variable vprio, Variable vz) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("sk_value")
		and target_7.getType().hasName("void *")
		and target_7.getArgument(0).(ConditionalExpr).getType().hasName("stack_st_SSL_CIPHER *")
		and target_7.getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio
		and target_7.getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getArgument(1).(VariableAccess).getTarget()=vz)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="0"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(ConditionalExpr target_10 |
		target_10.getType().hasName("SSL_CIPHER *")
		and target_10.getCondition() instanceof Literal
		and target_10.getThen() instanceof FunctionCall
		and target_10.getElse() instanceof Literal
		and target_10.getEnclosingFunction() = func)
}

from Function func, Parameter vs, Variable vprio, Variable vallow, Variable vz
where
func_0(func)
and func_1(func)
and not func_2(vprio, vz)
and not func_3(vprio, vallow, vz)
and not func_5(vs)
and func_7(vprio, vz)
and func_8(func)
and func_9(func)
and func_10(func)
and vs.getType().hasName("SSL *")
and vprio.getType().hasName("stack_st_SSL_CIPHER *")
and vallow.getType().hasName("stack_st_SSL_CIPHER *")
and vz.getType().hasName("int")
and vs.getParentScope+() = func
and vprio.getParentScope+() = func
and vallow.getParentScope+() = func
and vz.getParentScope+() = func
select func, vs, vprio, vallow, vz
