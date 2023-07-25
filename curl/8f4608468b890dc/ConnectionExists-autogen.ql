/**
 * @name curl-8f4608468b890dc-ConnectionExists
 * @id cpp/curl/8f4608468b890dc/ConnectionExists
 * @description curl-8f4608468b890dc-lib/url.c-ConnectionExists CVE-2023-27535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_1050, BitwiseAndExpr target_1, NotExpr target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("get_protocol_family")
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="12"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_timestrcmp")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_timestrcmp")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ccc"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ccc"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vneedle_1050, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(FunctionCall).getTarget().hasName("get_protocol_family")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_1.getRightOperand().(BitwiseOrExpr).getValue()="48"
}

predicate func_2(Parameter vneedle_1050, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("ssh_config_matches")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vneedle_1050
}

from Function func, Parameter vneedle_1050, BitwiseAndExpr target_1, NotExpr target_2
where
not func_0(vneedle_1050, target_1, target_2)
and func_1(vneedle_1050, target_1)
and func_2(vneedle_1050, target_2)
and vneedle_1050.getType().hasName("connectdata *")
and vneedle_1050.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
