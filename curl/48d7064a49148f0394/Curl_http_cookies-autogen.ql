/**
 * @name curl-48d7064a49148f0394-Curl_http_cookies
 * @id cpp/curl/48d7064a49148f0394/Curl-http-cookies
 * @description curl-48d7064a49148f0394-Curl_http_cookies CVE-2022-32205
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_6(Parameter vdata_2714, Parameter vr_2716, Variable vresult_2718, Variable vaddcookies_2719, Variable vcount_2726) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vcount_2726
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2718
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addn")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_2716
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie: "
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie: "
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_2718
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2718
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addf")
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_2716
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s%s"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vcount_2726
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="; "
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vaddcookies_2719
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcount_2726
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2714
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vaddcookies_2719)
}

predicate func_7(Parameter vr_2716, Variable vresult_2718, Variable vaddcookies_2719, Variable vcount_2726) {
	exists(LogicalAndExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getTarget()=vaddcookies_2719
		and target_7.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_2718
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vcount_2726
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2718
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addn")
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_2716
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie: "
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie: "
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_2718
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2718
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_dyn_addf")
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_2716
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s%s"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vcount_2726
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="; "
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vaddcookies_2719
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcount_2726)
}

predicate func_8(Parameter vdata_2714) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("Curl_share_lock")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vdata_2714)
}

predicate func_9(Parameter vdata_2714) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("Curl_share_unlock")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vdata_2714)
}

predicate func_10(Parameter vr_2716, Variable vco_2725, Variable vcount_2726) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("Curl_dyn_addf")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vr_2716
		and target_10.getArgument(1).(StringLiteral).getValue()="%s%s=%s"
		and target_10.getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vcount_2726
		and target_10.getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="; "
		and target_10.getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_10.getArgument(3).(PointerFieldAccess).getTarget().getName()="name"
		and target_10.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vco_2725
		and target_10.getArgument(4).(PointerFieldAccess).getTarget().getName()="value"
		and target_10.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vco_2725)
}

predicate func_11(Variable vco_2725) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="next"
		and target_11.getQualifier().(VariableAccess).getTarget()=vco_2725)
}

from Function func, Parameter vdata_2714, Parameter vr_2716, Variable vresult_2718, Variable vaddcookies_2719, Variable vco_2725, Variable vcount_2726
where
not func_0(func)
and not func_6(vdata_2714, vr_2716, vresult_2718, vaddcookies_2719, vcount_2726)
and func_7(vr_2716, vresult_2718, vaddcookies_2719, vcount_2726)
and vdata_2714.getType().hasName("Curl_easy *")
and func_8(vdata_2714)
and func_9(vdata_2714)
and vr_2716.getType().hasName("dynbuf *")
and func_10(vr_2716, vco_2725, vcount_2726)
and vresult_2718.getType().hasName("CURLcode")
and vaddcookies_2719.getType().hasName("char *")
and vco_2725.getType().hasName("Cookie *")
and func_11(vco_2725)
and vcount_2726.getType().hasName("int")
and vdata_2714.getParentScope+() = func
and vr_2716.getParentScope+() = func
and vresult_2718.getParentScope+() = func
and vaddcookies_2719.getParentScope+() = func
and vco_2725.getParentScope+() = func
and vcount_2726.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
