import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="41"
		and not target_0.getValue()="42"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="200"
		and not target_1.getValue()="201"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="212"
		and not target_2.getValue()="213"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="227"
		and not target_3.getValue()="228"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="311"
		and not target_4.getValue()="320"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="345"
		and not target_5.getValue()="351"
		and target_5.getEnclosingFunction() = func)
}

predicate func_9(Parameter vp, Parameter vctx, Variable vt, Variable vi) {
	exists(BlockStmt target_9 |
		target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_mul")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx
		and target_9.getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_9.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_9.getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_10(Variable vt) {
	exists(IfStmt target_10 |
		target_10.getCondition().(FunctionCall).getTarget().hasName("BN_is_one")
		and target_10.getCondition().(FunctionCall).getType().hasName("int")
		and target_10.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt)
}

predicate func_11(Variable ve, Variable vi) {
	exists(IfStmt target_11 |
		target_11.getCondition().(GEExpr).getType().hasName("int")
		and target_11.getCondition().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_11.getCondition().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=ve
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="121"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="111"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/bn/bn_sqrt.c"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="320")
}

predicate func_12(Variable vi) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getType().hasName("int")
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_13(Parameter vp, Parameter vctx, Variable vb, Variable vt) {
	exists(IfStmt target_13 |
		target_13.getCondition().(NotExpr).getType().hasName("int")
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_sqr")
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vb
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx)
}

predicate func_14(Variable vt) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("BN_is_one")
		and target_14.getType().hasName("int")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vt)
}

predicate func_15(Variable vi) {
	exists(PostfixIncrExpr target_15 |
		target_15.getType().hasName("int")
		and target_15.getOperand().(VariableAccess).getTarget()=vi)
}

predicate func_16(Parameter vp, Parameter vctx, Variable vt) {
	exists(IfStmt target_16 |
		target_16.getCondition().(NotExpr).getType().hasName("int")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_mul")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx)
}

predicate func_19(Variable ve, Variable vi, Function func) {
	exists(WhileStmt target_19 |
		target_19.getCondition().(NotExpr).getType().hasName("int")
		and target_19.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof PostfixIncrExpr
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(VariableAccess).getTarget()=ve
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="121"
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="111"
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/bn/bn_sqrt.c"
		and target_19.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_19.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_19.getEnclosingFunction() = func)
}

from Function func, Parameter vp, Parameter vctx, Variable vb, Variable vt, Variable ve, Variable vi
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and not func_9(vp, vctx, vt, vi)
and not func_10(vt)
and not func_11(ve, vi)
and func_12(vi)
and func_13(vp, vctx, vb, vt)
and func_14(vt)
and func_15(vi)
and func_16(vp, vctx, vt)
and func_19(ve, vi, func)
and vp.getType().hasName("const BIGNUM *")
and vctx.getType().hasName("BN_CTX *")
and vb.getType().hasName("BIGNUM *")
and vt.getType().hasName("BIGNUM *")
and ve.getType().hasName("int")
and vi.getType().hasName("int")
and vp.getParentScope+() = func
and vctx.getParentScope+() = func
and vb.getParentScope+() = func
and vt.getParentScope+() = func
and ve.getParentScope+() = func
and vi.getParentScope+() = func
select func, vp, vctx, vb, vt, ve, vi
