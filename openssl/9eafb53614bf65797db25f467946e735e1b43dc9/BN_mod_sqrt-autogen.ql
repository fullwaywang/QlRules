import cpp

predicate func_3(Parameter vp, Parameter vctx, Variable vt, Variable vi) {
	exists(BlockStmt target_3 |
		target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_mul")
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp
		and target_3.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx
		and target_3.getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_3.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_3.getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_4(Variable vt) {
	exists(IfStmt target_4 |
		target_4.getCondition().(FunctionCall).getTarget().hasName("BN_is_one")
		and target_4.getCondition().(FunctionCall).getType().hasName("int")
		and target_4.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt)
}

predicate func_5(Variable ve, Variable vi, Variable v__func__, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(GEExpr).getType().hasName("int")
		and target_5.getCondition().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_5.getCondition().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=ve
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getType().hasName("void")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="3"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="111"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vi) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_7(Parameter vp, Parameter vctx, Variable vb, Variable vt) {
	exists(IfStmt target_7 |
		target_7.getCondition().(NotExpr).getType().hasName("int")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_sqr")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vb
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx)
}

predicate func_8(Variable vt) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("BN_is_one")
		and target_8.getType().hasName("int")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vt)
}

predicate func_9(Variable vi) {
	exists(PostfixIncrExpr target_9 |
		target_9.getType().hasName("int")
		and target_9.getOperand().(VariableAccess).getTarget()=vi)
}

predicate func_10(Parameter vp, Parameter vctx, Variable vt) {
	exists(IfStmt target_10 |
		target_10.getCondition().(NotExpr).getType().hasName("int")
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_mul")
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx)
}

predicate func_13(Variable ve, Variable vi, Variable v__func__, Function func) {
	exists(WhileStmt target_13 |
		target_13.getCondition().(NotExpr).getType().hasName("int")
		and target_13.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof PostfixIncrExpr
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(VariableAccess).getTarget()=ve
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="3"
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="111"
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_13.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_13.getEnclosingFunction() = func)
}

from Function func, Parameter vp, Parameter vctx, Variable vb, Variable vt, Variable ve, Variable vi, Variable v__func__
where
not func_3(vp, vctx, vt, vi)
and not func_4(vt)
and not func_5(ve, vi, v__func__, func)
and func_6(vi)
and func_7(vp, vctx, vb, vt)
and func_8(vt)
and func_9(vi)
and func_10(vp, vctx, vt)
and func_13(ve, vi, v__func__, func)
and vp.getType().hasName("const BIGNUM *")
and vctx.getType().hasName("BN_CTX *")
and vb.getType().hasName("BIGNUM *")
and vt.getType().hasName("BIGNUM *")
and ve.getType().hasName("int")
and vi.getType().hasName("int")
and v__func__.getType().hasName("const char[12]")
and vp.getParentScope+() = func
and vctx.getParentScope+() = func
and vb.getParentScope+() = func
and vt.getParentScope+() = func
and ve.getParentScope+() = func
and vi.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, vp, vctx, vb, vt, ve, vi, v__func__
