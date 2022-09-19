import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="458"
		and not target_0.getValue()="472"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="480"
		and not target_1.getValue()="494"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="502"
		and not target_2.getValue()="516"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vctx, Parameter vinl, Variable vb) {
	exists(IfStmt target_3 |
		target_3.getCondition().(GTExpr).getType().hasName("int")
		and target_3.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getType().hasName("unsigned int")
		and target_3.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinl
		and target_3.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getType().hasName("unsigned int")
		and target_3.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb
		and target_3.getCondition().(GTExpr).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(GTExpr).getLesserOperand().(SubExpr).getType().hasName("unsigned int")
		and target_3.getCondition().(GTExpr).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(GTExpr).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vb
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="6"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="166"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="184"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/evp/evp_enc.c"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="529"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="final_used"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getType().hasName("int")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx)
}

from Function func, Parameter vctx, Parameter vinl, Variable vb
where
func_0(func)
and func_1(func)
and func_2(func)
and not func_3(vctx, vinl, vb)
and vctx.getType().hasName("EVP_CIPHER_CTX *")
and vinl.getType().hasName("int")
and vb.getType().hasName("unsigned int")
and vctx.getParentScope+() = func
and vinl.getParentScope+() = func
and vb.getParentScope+() = func
select func, vctx, vinl, vb
