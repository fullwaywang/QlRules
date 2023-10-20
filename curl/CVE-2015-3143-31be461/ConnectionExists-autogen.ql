/**
 * @name curl-31be461c6b659312100c47be6ddd5f0f569290f6-ConnectionExists
 * @id cpp/curl/31be461c6b659312100c47be6ddd5f0f569290f6/ConnectionExists
 * @description curl-31be461c6b659312100c47be6ddd5f0f569290f6-lib/url.c-ConnectionExists CVE-2015-3143
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcheck_3069, Variable vwantNTLMhttp_3072, BlockStmt target_2, LogicalOrExpr target_3, LogicalOrExpr target_4, IfStmt target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3072
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ntlm"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3072
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwantNTLMhttp_3072, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vwantNTLMhttp_3072
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vcheck_3069, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;"
}

predicate func_3(Variable vcheck_3069, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localport"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localport"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localportrange"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localportrange"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="localdev"
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="localdev"
}

predicate func_4(Variable vcheck_3069, LogicalOrExpr target_4) {
		target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3069
}

predicate func_5(Variable vcheck_3069, Variable vwantNTLMhttp_3072, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vwantNTLMhttp_3072
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ntlm"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcheck_3069
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcheck_3069
}

from Function func, Variable vcheck_3069, Variable vwantNTLMhttp_3072, VariableAccess target_1, BlockStmt target_2, LogicalOrExpr target_3, LogicalOrExpr target_4, IfStmt target_5
where
not func_0(vcheck_3069, vwantNTLMhttp_3072, target_2, target_3, target_4, target_5)
and func_1(vwantNTLMhttp_3072, target_2, target_1)
and func_2(vcheck_3069, target_2)
and func_3(vcheck_3069, target_3)
and func_4(vcheck_3069, target_4)
and func_5(vcheck_3069, vwantNTLMhttp_3072, target_5)
and vcheck_3069.getType().hasName("connectdata *")
and vwantNTLMhttp_3072.getType().hasName("bool")
and vcheck_3069.getParentScope+() = func
and vwantNTLMhttp_3072.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
