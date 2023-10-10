/**
 * @name redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-setrangeCommand
 * @id cpp/redis/6c25c6b7da116e110e89a5db45eeae743879e7ea/setrangeCommand
 * @description redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-src/t_string.c-setrangeCommand CVE-2022-35977
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvalue_440, FunctionCall target_0) {
		target_0.getTarget().hasName("sdslen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vvalue_440
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof AddExpr
}

predicate func_1(Variable vvalue_440, FunctionCall target_1) {
		target_1.getTarget().hasName("sdslen")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vvalue_440
		and target_1.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_1.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_1.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof AddExpr
}

predicate func_2(Variable voffset_439, VariableAccess target_2) {
		target_2.getTarget()=voffset_439
		and target_2.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_2.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_2.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof AddExpr
}

predicate func_3(Variable voffset_439, VariableAccess target_3) {
		target_3.getTarget()=voffset_439
		and target_3.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_3.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_3.getParent().(AddExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof AddExpr
}

predicate func_4(Variable voffset_439, RelationalOperation target_6, AddExpr target_7, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=voffset_439
		and target_4.getAnOperand() instanceof FunctionCall
		and target_4.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_4.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_6.getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
}

predicate func_5(Variable voffset_439, AddExpr target_7, AddExpr target_8, AddExpr target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=voffset_439
		and target_5.getAnOperand() instanceof FunctionCall
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable voffset_439, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=voffset_439
		and target_6.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_7(Variable voffset_439, Variable vvalue_440, AddExpr target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=voffset_439
		and target_7.getAnOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_7.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_440
}

predicate func_8(Variable voffset_439, Variable vvalue_440, AddExpr target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=voffset_439
		and target_8.getAnOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_440
}

from Function func, Variable voffset_439, Variable vvalue_440, FunctionCall target_0, FunctionCall target_1, VariableAccess target_2, VariableAccess target_3, AddExpr target_4, AddExpr target_5, RelationalOperation target_6, AddExpr target_7, AddExpr target_8
where
func_0(vvalue_440, target_0)
and func_1(vvalue_440, target_1)
and func_2(voffset_439, target_2)
and func_3(voffset_439, target_3)
and func_4(voffset_439, target_6, target_7, target_4)
and func_5(voffset_439, target_7, target_8, target_5)
and func_6(voffset_439, target_6)
and func_7(voffset_439, vvalue_440, target_7)
and func_8(voffset_439, vvalue_440, target_8)
and voffset_439.getType().hasName("long")
and vvalue_440.getType().hasName("sds")
and voffset_439.(LocalVariable).getFunction() = func
and vvalue_440.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
