import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2008"
		and not target_0.getValue()="2014"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2017"
		and not target_1.getValue()="2023"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2025"
		and not target_2.getValue()="2031"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="2045"
		and not target_3.getValue()="2051"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="2051"
		and not target_4.getValue()="2057"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="2070"
		and not target_5.getValue()="2076"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="2080"
		and not target_6.getValue()="2091"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="2092"
		and not target_7.getValue()="2103"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="2100"
		and not target_8.getValue()="2111"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="2104"
		and not target_9.getValue()="2115"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vs, Variable vnc, Variable vllen) {
	exists(IfStmt target_10 |
		target_10.getCondition().(GTExpr).getType().hasName("int")
		and target_10.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_10.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vnc
		and target_10.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="2"
		and target_10.getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="50"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="135"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="132"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_clnt.c"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2083")
}

predicate func_13(Parameter vs, Variable vnc, Variable vl, Variable vllen) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_13.getExpr().(FunctionCall).getType().hasName("int")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_13.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_13.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="50"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vnc
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen)
}

predicate func_15(Function func) {
	exists(GotoStmt target_15 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_15)
}

from Function func, Parameter vs, Variable vnc, Variable vl, Variable vllen, Variable vp, Variable vq
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
and not func_10(vs, vnc, vllen)
and func_13(vs, vnc, vl, vllen)
and func_15(func)
and vs.getType().hasName("SSL *")
and vnc.getType().hasName("unsigned long")
and vl.getType().hasName("unsigned long")
and vllen.getType().hasName("unsigned int")
and vp.getType().hasName("const unsigned char *")
and vq.getType().hasName("const unsigned char *")
and vs.getParentScope+() = func
and vnc.getParentScope+() = func
and vl.getParentScope+() = func
and vllen.getParentScope+() = func
and vp.getParentScope+() = func
and vq.getParentScope+() = func
select func, vs, vnc, vl, vllen, vp, vq
