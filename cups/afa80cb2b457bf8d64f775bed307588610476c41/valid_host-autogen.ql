/**
 * @name cups-afa80cb2b457bf8d64f775bed307588610476c41-valid_host
 * @id cpp/cups/afa80cb2b457bf8d64f775bed307588610476c41/valid-host
 * @description cups-afa80cb2b457bf8d64f775bed307588610476c41-scheduler/client.c-valid_host CVE-2017-18190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcon_3858, LogicalOrExpr target_0) {
		target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clientname"
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcon_3858
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="localhost"
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clientname"
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcon_3858
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="localhost."
}

predicate func_1(Parameter vcon_3858, LogicalOrExpr target_1) {
		target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clientname"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcon_3858
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="localhost.localdomain"
}

from Function func, Parameter vcon_3858, LogicalOrExpr target_0, LogicalOrExpr target_1
where
func_0(vcon_3858, target_0)
and func_1(vcon_3858, target_1)
and vcon_3858.getType().hasName("cupsd_client_t *")
and vcon_3858.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
