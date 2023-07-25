/**
 * @name libmodbus-b4ef4c17d618eba0adccc4c7d9e9a1ef809fc9b6-modbus_reply
 * @id cpp/libmodbus/b4ef4c17d618eba0adccc4c7d9e9a1ef809fc9b6/modbus-reply
 * @description libmodbus-b4ef4c17d618eba0adccc4c7d9e9a1ef809fc9b6-src/modbus.c-modbus_reply CVE-2022-0367
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmapping_address_952, LogicalOrExpr target_1, ConditionalExpr target_2, VariableAccess target_0) {
		target_0.getTarget()=vmapping_address_952
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vmapping_address_952, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmapping_address_952
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmapping_address_952
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="nb_registers"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmapping_address_952
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="nb_registers"
}

predicate func_2(Variable vmapping_address_952, ConditionalExpr target_2) {
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmapping_address_952
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vmapping_address_952, VariableAccess target_0, LogicalOrExpr target_1, ConditionalExpr target_2
where
func_0(vmapping_address_952, target_1, target_2, target_0)
and func_1(vmapping_address_952, target_1)
and func_2(vmapping_address_952, target_2)
and vmapping_address_952.getType().hasName("int")
and vmapping_address_952.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
