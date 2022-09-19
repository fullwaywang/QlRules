import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("bool")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
		and target_0.getEnclosingFunction() = func)
}

predicate func_4(Parameter vdata, Parameter vr, Variable vresult, Variable vaddcookies, Variable vcount) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_4.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_4.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(VariableAccess).getTarget()=vaddcookies
		and target_4.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_4.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult
		and target_4.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vcount
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addn")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie: "
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie: "
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addf")
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s%s"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vcount
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="; "
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vaddcookies
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcount
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(VariableAccess).getTarget()=vaddcookies)
}

predicate func_5(Parameter vr, Variable vresult, Variable vaddcookies, Variable vcount) {
	exists(LogicalAndExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLeftOperand().(VariableAccess).getTarget()=vaddcookies
		and target_5.getRightOperand().(NotExpr).getType().hasName("int")
		and target_5.getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vcount
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addn")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie: "
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie: "
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addf")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s%s"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vcount
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="; "
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vaddcookies
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcount)
}

from Function func, Parameter vdata, Parameter vr, Variable vresult, Variable vaddcookies, Variable vco, Variable vcount
where
not func_0(func)
and not func_4(vdata, vr, vresult, vaddcookies, vcount)
and func_5(vr, vresult, vaddcookies, vcount)
and vdata.getType().hasName("Curl_easy *")
and vr.getType().hasName("dynbuf *")
and vresult.getType().hasName("CURLcode")
and vaddcookies.getType().hasName("char *")
and vco.getType().hasName("Cookie *")
and vcount.getType().hasName("int")
and vdata.getParentScope+() = func
and vr.getParentScope+() = func
and vresult.getParentScope+() = func
and vaddcookies.getParentScope+() = func
and vco.getParentScope+() = func
and vcount.getParentScope+() = func
select func, vdata, vr, vresult, vaddcookies, vco, vcount
