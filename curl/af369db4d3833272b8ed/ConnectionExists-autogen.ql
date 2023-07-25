/**
 * @name curl-af369db4d3833272b8ed-ConnectionExists
 * @id cpp/curl/af369db4d3833272b8ed/ConnectionExists
 * @description curl-af369db4d3833272b8ed-lib/url.c-ConnectionExists CVE-2023-27538
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(BitwiseAndExpr target_0 |
		target_0.getLeftOperand() instanceof FunctionCall
		and target_0.getRightOperand() instanceof BitwiseOrExpr
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_1(Parameter vneedle_1077, FunctionCall target_1) {
		target_1.getTarget().hasName("get_protocol_family")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1077
}

*/
predicate func_2(Parameter vneedle_1077, BlockStmt target_4, BitwiseOrExpr target_2) {
		target_2.getValue()="48"
		and target_2.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_protocol_family")
		and target_2.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_2.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1077
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(BlockStmt target_4, Function func, EqualityOperation target_3) {
		target_3.getAnOperand() instanceof FunctionCall
		and target_3.getAnOperand() instanceof BitwiseOrExpr
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(IfStmt).getCondition().(NotExpr).getValue()="1"
		and target_4.getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
}

from Function func, Parameter vneedle_1077, BitwiseOrExpr target_2, EqualityOperation target_3, BlockStmt target_4
where
not func_0(target_4, func)
and func_2(vneedle_1077, target_4, target_2)
and func_3(target_4, func, target_3)
and func_4(target_4)
and vneedle_1077.getType().hasName("connectdata *")
and vneedle_1077.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()