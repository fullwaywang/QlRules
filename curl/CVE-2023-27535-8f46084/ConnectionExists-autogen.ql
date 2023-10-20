/**
 * @name curl-8f4608468b890dc-ConnectionExists
 * @id cpp/curl/8f4608468b890dc/ConnectionExists
 * @description curl-8f4608468b890dc-lib/url.c-ConnectionExists CVE-2023-27535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_1050, BlockStmt target_3, BitwiseOrExpr target_0) {
		target_0.getValue()="48"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("get_protocol_family")
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_0.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_1(Parameter vneedle_1050, Variable vcheck_1055, LogicalOrExpr target_4, PointerFieldAccess target_5) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_timestrcmp")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="account"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="account"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_timestrcmp")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1055
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ccc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ccc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ftpc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1055
		and target_1.getParent().(IfStmt).getThen() instanceof ContinueStmt
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, NotExpr target_2) {
		target_2.getValue()="1"
		and target_2.getParent().(IfStmt).getThen() instanceof ContinueStmt
		and target_2.getEnclosingFunction() = func
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(IfStmt).getCondition() instanceof NotExpr
}

predicate func_4(Parameter vneedle_1050, LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="httpproxy"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
		and target_4.getAnOperand().(ValueFieldAccess).getTarget().getName()="tunnel_proxy"
		and target_4.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_4.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1050
}

predicate func_5(Variable vcheck_1055, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="scheme"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1055
}

from Function func, Parameter vneedle_1050, Variable vcheck_1055, BitwiseOrExpr target_0, NotExpr target_2, BlockStmt target_3, LogicalOrExpr target_4, PointerFieldAccess target_5
where
func_0(vneedle_1050, target_3, target_0)
and not func_1(vneedle_1050, vcheck_1055, target_4, target_5)
and func_2(func, target_2)
and func_3(target_3)
and func_4(vneedle_1050, target_4)
and func_5(vcheck_1055, target_5)
and vneedle_1050.getType().hasName("connectdata *")
and vcheck_1055.getType().hasName("connectdata *")
and vneedle_1050.getFunction() = func
and vcheck_1055.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
