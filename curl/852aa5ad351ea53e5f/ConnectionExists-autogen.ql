/**
 * @name curl-852aa5ad351ea53e5f-ConnectionExists
 * @id cpp/curl/852aa5ad351ea53e5f/ConnectionExists
 * @description curl-852aa5ad351ea53e5f-ConnectionExists CVE-2022-22576
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_1115, Variable vcheck_1120) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_safecmp")
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sasl_authzid"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1115
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sasl_authzid"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1120
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_safecmp")
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1115
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1120
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;")
}

predicate func_1(Parameter vneedle_1115, Variable vcheck_1120) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1115
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1120
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_1115
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_1120
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;")
}

predicate func_2(Parameter vneedle_1115) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="handler"
		and target_2.getQualifier().(VariableAccess).getTarget()=vneedle_1115)
}

predicate func_3(Variable vcheck_1120) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="localdev"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcheck_1120)
}

from Function func, Parameter vneedle_1115, Variable vcheck_1120
where
not func_0(vneedle_1115, vcheck_1120)
and func_1(vneedle_1115, vcheck_1120)
and vneedle_1115.getType().hasName("connectdata *")
and func_2(vneedle_1115)
and vcheck_1120.getType().hasName("connectdata *")
and func_3(vcheck_1120)
and vneedle_1115.getParentScope+() = func
and vcheck_1120.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
