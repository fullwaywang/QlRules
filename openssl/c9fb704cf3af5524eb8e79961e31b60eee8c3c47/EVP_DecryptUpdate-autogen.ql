import cpp

predicate func_0(Parameter vinl, Variable vb, Variable v__func__, Parameter vctx, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(GTExpr).getType().hasName("int")
		and target_0.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getType().hasName("unsigned int")
		and target_0.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinl
		and target_0.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getType().hasName("unsigned int")
		and target_0.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb
		and target_0.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(GTExpr).getLesserOperand().(SubExpr).getType().hasName("unsigned int")
		and target_0.getCondition().(GTExpr).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(GTExpr).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vb
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getType().hasName("void")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="202"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="final_used"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx)
}

from Function func, Parameter vinl, Variable vb, Variable v__func__, Parameter vctx
where
not func_0(vinl, vb, v__func__, vctx, func)
and vinl.getType().hasName("int")
and vb.getType().hasName("unsigned int")
and v__func__.getType().hasName("const char[18]")
and vctx.getType().hasName("EVP_CIPHER_CTX *")
and vinl.getParentScope+() = func
and vb.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vctx.getParentScope+() = func
select func, vinl, vb, v__func__, vctx
