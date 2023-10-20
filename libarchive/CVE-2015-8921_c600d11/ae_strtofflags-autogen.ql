/**
 * @name libarchive-c600d11f2c1645f6f6965592659d386436f4d6db-ae_strtofflags
 * @id cpp/libarchive/c600d11f2c1645f6f6965592659d386436f4d6db/ae-strtofflags
 * @description libarchive-c600d11f2c1645f6f6965592659d386436f4d6db-libarchive/archive_entry.c-ae_strtofflags CVE-2015-8921
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1747, LogicalAndExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_1747
		and target_0.getExpr().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstart_1730, Variable vend_1730, PointerArithmeticOperation target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vend_1730
		and target_1.getRightOperand().(VariableAccess).getTarget()=vstart_1730
}

predicate func_2(Function func, Initializer target_2) {
		target_2.getExpr() instanceof PointerArithmeticOperation
		and target_2.getExpr().getEnclosingFunction() = func
}

predicate func_3(Variable vstart_1730, Variable vlength_1747, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1747
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1730
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_1747
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vstart_1730, Variable vend_1730, Variable vlength_1747, PointerArithmeticOperation target_1, Initializer target_2, LogicalAndExpr target_3
where
not func_0(vlength_1747, target_3)
and func_1(vstart_1730, vend_1730, target_1)
and func_2(func, target_2)
and func_3(vstart_1730, vlength_1747, target_3)
and vstart_1730.getType().hasName("const char *")
and vend_1730.getType().hasName("const char *")
and vlength_1747.getType().hasName("size_t")
and vstart_1730.getParentScope+() = func
and vend_1730.getParentScope+() = func
and vlength_1747.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
