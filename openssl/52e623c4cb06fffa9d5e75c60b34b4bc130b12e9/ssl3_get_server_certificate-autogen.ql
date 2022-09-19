import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1150"
		and not target_0.getValue()="1156"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1158"
		and not target_1.getValue()="1164"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1164"
		and not target_2.getValue()="1170"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1168"
		and not target_3.getValue()="1174"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1185"
		and not target_4.getValue()="1191"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1229"
		and not target_5.getValue()="1235"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="1238"
		and not target_6.getValue()="1244"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="1244"
		and not target_7.getValue()="1250"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1256"
		and not target_8.getValue()="1262"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Variable val, Variable vnc, Variable vllen) {
	exists(IfStmt target_9 |
		target_9.getCondition().(GTExpr).getType().hasName("int")
		and target_9.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_9.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vnc
		and target_9.getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="3"
		and target_9.getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="144"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="135"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_clnt.c"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1149")
}

predicate func_11(Variable val, Variable vnc, Variable vllen, Variable vl) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vnc
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="3"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vllen)
}

from Function func, Variable val, Variable vnc, Variable vllen, Variable vl, Variable vq, Variable vp
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
and not func_9(val, vnc, vllen)
and func_11(val, vnc, vllen, vl)
and val.getType().hasName("int")
and vnc.getType().hasName("unsigned long")
and vllen.getType().hasName("unsigned long")
and vl.getType().hasName("unsigned long")
and vq.getType().hasName("const unsigned char *")
and vp.getType().hasName("const unsigned char *")
and val.getParentScope+() = func
and vnc.getParentScope+() = func
and vllen.getParentScope+() = func
and vl.getParentScope+() = func
and vq.getParentScope+() = func
and vp.getParentScope+() = func
select func, val, vnc, vllen, vl, vq, vp
