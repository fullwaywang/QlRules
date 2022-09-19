import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="5"
		and not target_0.getValue()="43"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="3212"
		and not target_1.getValue()="3232"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="3224"
		and not target_2.getValue()="3217"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="3235"
		and not target_3.getValue()="3228"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="3239"
		and not target_4.getValue()="3232"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="3246"
		and not target_5.getValue()="3239"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="3258"
		and not target_6.getValue()="3251"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="3277"
		and not target_7.getValue()="3270"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="3281"
		and not target_8.getValue()="3274"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="3285"
		and not target_9.getValue()="3278"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vs) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="options"
		and target_10.getType().hasName("unsigned long")
		and target_10.getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_11(Variable vret) {
	exists(ReturnStmt target_11 |
		target_11.getExpr().(VariableAccess).getTarget()=vret
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_14(Parameter vparg, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_14.getExpr().(FunctionCall).getType().hasName("void")
		and target_14.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="213"
		and target_14.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="43"
		and target_14.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_lib.c"
		and target_14.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_14.getEnclosingFunction() = func
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_KEY_up_ref")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparg)
}

predicate func_18(Variable vdh, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(NotExpr).getType().hasName("int")
		and target_18.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_18.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_18.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DH_free")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="213"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_lib.c"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_18.getEnclosingFunction() = func)
}

from Function func, Parameter vparg, Variable vret, Variable vdh, Variable vecdh, Parameter vs
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(vs)
and func_11(vret)
and func_14(vparg, func)
and func_18(vdh, func)
and vparg.getType().hasName("void *")
and vret.getType().hasName("int")
and vdh.getType().hasName("DH *")
and vecdh.getType().hasName("EC_KEY *")
and vs.getType().hasName("SSL *")
and vparg.getParentScope+() = func
and vret.getParentScope+() = func
and vdh.getParentScope+() = func
and vecdh.getParentScope+() = func
and vs.getParentScope+() = func
select func, vparg, vret, vdh, vecdh, vs
