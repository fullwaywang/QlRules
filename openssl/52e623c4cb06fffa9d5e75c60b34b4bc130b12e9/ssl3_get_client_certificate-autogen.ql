import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="3241"
		and not target_0.getValue()="3247"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="3248"
		and not target_1.getValue()="3254"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="3254"
		and not target_2.getValue()="3260"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="3258"
		and not target_3.getValue()="3264"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="3270"
		and not target_4.getValue()="3276"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="3277"
		and not target_5.getValue()="3283"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="3291"
		and not target_6.getValue()="3297"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="3308"
		and not target_7.getValue()="3314"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable val, Variable vnc, Variable vllen) {
	exists(IfStmt target_8 |
		target_8.getCondition().(GTExpr).getType().hasName("int")
		and target_8.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_8.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vnc
		and target_8.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="3"
		and target_8.getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="137"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="135"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="3240")
}

predicate func_10(Variable val, Variable vl, Variable vnc, Variable vllen) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getType().hasName("int")
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vnc
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="3"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen)
}

from Function func, Variable val, Variable vl, Variable vnc, Variable vllen, Variable vp, Variable vq
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and not func_8(val, vnc, vllen)
and func_10(val, vl, vnc, vllen)
and val.getType().hasName("int")
and vl.getType().hasName("unsigned long")
and vnc.getType().hasName("unsigned long")
and vllen.getType().hasName("unsigned long")
and vp.getType().hasName("const unsigned char *")
and vq.getType().hasName("const unsigned char *")
and val.getParentScope+() = func
and vl.getParentScope+() = func
and vnc.getParentScope+() = func
and vllen.getParentScope+() = func
and vp.getParentScope+() = func
and vq.getParentScope+() = func
select func, val, vl, vnc, vllen, vp, vq
