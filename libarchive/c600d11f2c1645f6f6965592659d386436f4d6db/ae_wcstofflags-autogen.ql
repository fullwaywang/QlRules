/**
 * @name libarchive-c600d11f2c1645f6f6965592659d386436f4d6db-ae_wcstofflags
 * @id cpp/libarchive/c600d11f2c1645f6f6965592659d386436f4d6db/ae-wcstofflags
 * @description libarchive-c600d11f2c1645f6f6965592659d386436f4d6db-libarchive/archive_entry.c-ae_wcstofflags CVE-2015-8921
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1814, LogicalAndExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_1814
		and target_0.getExpr().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstart_1797, Variable vend_1797, PointerArithmeticOperation target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vend_1797
		and target_1.getRightOperand().(VariableAccess).getTarget()=vstart_1797
}

predicate func_2(Function func, Initializer target_2) {
		target_2.getExpr() instanceof PointerArithmeticOperation
		and target_2.getExpr().getEnclosingFunction() = func
}

predicate func_3(Variable vstart_1797, Variable vlength_1814, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1814
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("wmemcmp")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1797
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="wname"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_1814
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vstart_1797, Variable vend_1797, Variable vlength_1814, PointerArithmeticOperation target_1, Initializer target_2, LogicalAndExpr target_3
where
not func_0(vlength_1814, target_3)
and func_1(vstart_1797, vend_1797, target_1)
and func_2(func, target_2)
and func_3(vstart_1797, vlength_1814, target_3)
and vstart_1797.getType().hasName("const wchar_t *")
and vend_1797.getType().hasName("const wchar_t *")
and vlength_1814.getType().hasName("size_t")
and vstart_1797.getParentScope+() = func
and vend_1797.getParentScope+() = func
and vlength_1814.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
