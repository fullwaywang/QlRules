/**
 * @name libtiff-b5a935d96b21cda0f434230cdf8ca958cd8b4eef-main
 * @id cpp/libtiff/b5a935d96b21cda0f434230cdf8ca958cd8b4eef/main
 * @description libtiff-b5a935d96b21cda0f434230cdf8ca958cd8b4eef-tools/tiff2rgba.c-main CVE-2020-35521
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="c:r:t:bn8h"
		and not target_0.getValue()="c:r:t:bn8hM:"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(SwitchCase target_1 |
		target_1.getExpr().(CharLiteral).getValue()="77"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(VariableAccess target_4, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("tmsize_t")
		and target_2.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("strtoul")
		and target_2.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="20"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(VariableAccess target_4, Function func) {
	exists(BreakStmt target_3 |
		target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vc_72, VariableAccess target_4) {
		target_4.getTarget()=vc_72
}

from Function func, Variable vc_72, StringLiteral target_0, VariableAccess target_4
where
func_0(func, target_0)
and not func_1(func)
and not func_2(target_4, func)
and not func_3(target_4, func)
and func_4(vc_72, target_4)
and vc_72.getType().hasName("int")
and vc_72.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
