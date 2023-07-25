/**
 * @name cups-de4f8c196106033e4c372dce3e91b9d42b0b9444-ctcompare
 * @id cpp/cups/de4f8c196106033e4c372dce3e91b9d42b0b9444/ctcompare
 * @description cups-de4f8c196106033e4c372dce3e91b9d42b0b9444-scheduler/cert.c-ctcompare CVE-2022-26691
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vb_435, Variable vresult_437, Parameter va_434, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(BitwiseOrExpr target_0 |
		target_0.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vresult_437
		and target_0.getLeftOperand().(BitwiseOrExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_434
		and target_0.getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_435
		and target_2.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(BitwiseOrExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vresult_437, VariableAccess target_1) {
		target_1.getTarget()=vresult_437
}

predicate func_2(Parameter vb_435, ExprStmt target_2) {
		target_2.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vb_435
}

predicate func_3(Parameter vb_435, Variable vresult_437, Parameter va_434, ExprStmt target_3) {
		target_3.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vresult_437
		and target_3.getExpr().(AssignOrExpr).getRValue().(BitwiseXorExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_434
		and target_3.getExpr().(AssignOrExpr).getRValue().(BitwiseXorExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_435
}

predicate func_4(Parameter va_434, ExprStmt target_4) {
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=va_434
}

from Function func, Parameter vb_435, Variable vresult_437, Parameter va_434, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vb_435, vresult_437, va_434, target_2, target_3, target_4)
and func_1(vresult_437, target_1)
and func_2(vb_435, target_2)
and func_3(vb_435, vresult_437, va_434, target_3)
and func_4(va_434, target_4)
and vb_435.getType().hasName("const char *")
and vresult_437.getType().hasName("int")
and va_434.getType().hasName("const char *")
and vb_435.getParentScope+() = func
and vresult_437.getParentScope+() = func
and va_434.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
