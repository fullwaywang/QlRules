import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="3689"
		and not target_0.getValue()="3682"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="3701"
		and not target_1.getValue()="3694"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="3713"
		and not target_2.getValue()="3706"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="5"
		and not target_3.getValue()="43"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="3718"
		and not target_4.getValue()="3730"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="3733"
		and not target_5.getValue()="3719"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="3744"
		and not target_6.getValue()="3730"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="3749"
		and not target_7.getValue()="3735"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="3755"
		and not target_8.getValue()="3741"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="3769"
		and not target_9.getValue()="3755"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="3785"
		and not target_10.getValue()="3771"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="3821"
		and not target_11.getValue()="3807"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="3825"
		and not target_12.getValue()="3811"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Parameter vctx) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="options"
		and target_13.getType().hasName("unsigned long")
		and target_13.getQualifier().(VariableAccess).getTarget()=vctx)
}

predicate func_14(Function func) {
	exists(ReturnStmt target_14 |
		target_14.getExpr().(Literal).getValue()="0"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr
		and target_14.getEnclosingFunction() = func)
}

predicate func_23(Variable vnew, Function func) {
	exists(IfStmt target_23 |
		target_23.getCondition().(NotExpr).getType().hasName("int")
		and target_23.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getType().hasName("unsigned long")
		and target_23.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_23.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_lib.c"
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DH_free")
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew
		and target_23.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_23.getEnclosingFunction() = func)
}

from Function func, Variable vnew, Variable vecdh, Parameter vctx, Parameter vlarg, Parameter vparg
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
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(vctx)
and func_14(func)
and func_23(vnew, func)
and vnew.getType().hasName("DH *")
and vecdh.getType().hasName("EC_KEY *")
and vctx.getType().hasName("SSL_CTX *")
and vlarg.getType().hasName("long")
and vparg.getType().hasName("void *")
and vnew.getParentScope+() = func
and vecdh.getParentScope+() = func
and vctx.getParentScope+() = func
and vlarg.getParentScope+() = func
and vparg.getParentScope+() = func
select func, vnew, vecdh, vctx, vlarg, vparg
