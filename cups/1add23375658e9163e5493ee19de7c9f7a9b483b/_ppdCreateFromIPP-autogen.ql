/**
 * @name cups-1add23375658e9163e5493ee19de7c9f7a9b483b-_ppdCreateFromIPP
 * @id cpp/cups/1add23375658e9163e5493ee19de7c9f7a9b483b/-ppdCreateFromIPP
 * @description cups-1add23375658e9163e5493ee19de7c9f7a9b483b-cups/ppd-cache.c-_ppdCreateFromIPP CVE-2017-15400
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfp_2933, Variable vformat_3102, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, LogicalAndExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/jpeg"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/png"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsFilePrintf")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"%s %s 0 -\"\n"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vformat_3102
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vformat_3102
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/pwg-raster"
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_0.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/urf"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsFilePrintf")
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"%s %s 100 -\"\n"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vformat_3102
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vformat_3102
		and target_0.getElse().(IfStmt).getElse() instanceof IfStmt
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vfp_2933, Variable vformat_3102, NotExpr target_2, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/vnd."
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/vnd."
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/tiff"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="text/"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsFilePrintf")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"%s %s 10 -\"\n"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vformat_3102
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vformat_3102
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vformat_3102, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_2.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/pdf"
}

predicate func_3(Variable vfp_2933, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("cupsFilePuts")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"application/vnd.cups-pdf application/pdf 10 -\"\n"
}

predicate func_4(Variable vfp_2933, Variable vformat_3102, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("cupsFilePrintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_2933
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*cupsFilter2: \"%s %s 10 -\"\n"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vformat_3102
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vformat_3102
}

predicate func_5(Variable vformat_3102, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/octet-stream"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/postscript"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="application/vnd."
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/vnd."
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="image/tiff"
		and target_5.getAnOperand().(FunctionCall).getTarget().hasName("_cups_strncasecmp")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vformat_3102
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="text/"
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
}

from Function func, Variable vfp_2933, Variable vformat_3102, IfStmt target_1, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, LogicalAndExpr target_5
where
not func_0(vfp_2933, vformat_3102, target_2, target_3, target_4, target_5)
and func_1(vfp_2933, vformat_3102, target_2, target_1)
and func_2(vformat_3102, target_2)
and func_3(vfp_2933, target_3)
and func_4(vfp_2933, vformat_3102, target_4)
and func_5(vformat_3102, target_5)
and vfp_2933.getType().hasName("cups_file_t *")
and vformat_3102.getType().hasName("const char *")
and vfp_2933.getParentScope+() = func
and vformat_3102.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
