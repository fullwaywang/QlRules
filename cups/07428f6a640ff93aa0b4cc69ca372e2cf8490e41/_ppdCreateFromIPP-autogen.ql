/**
 * @name cups-07428f6a640ff93aa0b4cc69ca372e2cf8490e41-_ppdCreateFromIPP
 * @id cpp/cups/07428f6a640ff93aa0b4cc69ca372e2cf8490e41/-ppdCreateFromIPP
 * @description cups-07428f6a640ff93aa0b4cc69ca372e2cf8490e41-cups/ppd-cache.c-_ppdCreateFromIPP CVE-2017-15400
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfp_2933, Variable vformat_3102, LogicalOrExpr target_1, IfStmt target_0) {
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/vnd."
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/vnd."
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/tiff"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="text/"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsFilePrintf")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"%s %s 10 -\"\n"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vformat_3102
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vformat_3102
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_1
}

predicate func_1(Variable vformat_3102, LogicalOrExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/jpeg"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/png"
}

from Function func, Variable vfp_2933, Variable vformat_3102, IfStmt target_0, LogicalOrExpr target_1
where
func_0(vfp_2933, vformat_3102, target_1, target_0)
and func_1(vformat_3102, target_1)
and vfp_2933.getType().hasName("cups_file_t *")
and vformat_3102.getType().hasName("const char *")
and vfp_2933.getParentScope+() = func
and vformat_3102.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
