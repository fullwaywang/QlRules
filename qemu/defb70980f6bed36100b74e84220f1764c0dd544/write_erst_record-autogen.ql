/**
 * @name qemu-defb70980f6bed36100b74e84220f1764c0dd544-write_erst_record
 * @id cpp/qemu/defb70980f6bed36100b74e84220f1764c0dd544/write-erst-record
 * @description qemu-defb70980f6bed36100b74e84220f1764c0dd544-hw/acpi/erst.c-write_erst_record CVE-2022-4172
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_658, Variable vexchange_length_661, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, SubExpr target_9) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vexchange_length_661
		and target_0.getRightOperand().(PointerFieldAccess).getTarget().getName()="record_offset"
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_658
		and target_0.getParent().(GTExpr).getGreaterOperand() instanceof AddExpr
		and target_0.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vexchange_length_661
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_658, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="record_offset"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_658
}

predicate func_2(Variable vrecord_length_664, VariableAccess target_2) {
		target_2.getTarget()=vrecord_length_664
}

predicate func_3(Variable vexchange_length_661, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vexchange_length_661
		and target_3.getParent().(GTExpr).getGreaterOperand() instanceof AddExpr
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vs_658, Variable vexchange_length_661, Variable vrecord_length_664, BlockStmt target_5, AddExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="record_offset"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_658
		and target_4.getAnOperand().(VariableAccess).getTarget()=vrecord_length_664
		and target_4.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vexchange_length_661
		and target_4.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="3"
}

predicate func_6(Parameter vs_658, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="record_offset"
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_658
}

predicate func_7(Parameter vs_658, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_erst_record")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_658
}

predicate func_8(Parameter vs_658, Variable vexchange_length_661, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="record_offset"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_658
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vexchange_length_661
		and target_8.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="128"
}

predicate func_9(Variable vexchange_length_661, Variable vrecord_length_664, SubExpr target_9) {
		target_9.getLeftOperand().(VariableAccess).getTarget()=vexchange_length_661
		and target_9.getRightOperand().(VariableAccess).getTarget()=vrecord_length_664
}

from Function func, Parameter vs_658, Variable vexchange_length_661, Variable vrecord_length_664, PointerFieldAccess target_1, VariableAccess target_2, VariableAccess target_3, AddExpr target_4, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, SubExpr target_9
where
not func_0(vs_658, vexchange_length_661, target_5, target_6, target_7, target_8, target_9)
and func_1(vs_658, target_1)
and func_2(vrecord_length_664, target_2)
and func_3(vexchange_length_661, target_5, target_3)
and func_4(vs_658, vexchange_length_661, vrecord_length_664, target_5, target_4)
and func_5(target_5)
and func_6(vs_658, target_6)
and func_7(vs_658, target_7)
and func_8(vs_658, vexchange_length_661, target_8)
and func_9(vexchange_length_661, vrecord_length_664, target_9)
and vs_658.getType().hasName("ERSTDeviceState *")
and vexchange_length_661.getType().hasName("unsigned int")
and vrecord_length_664.getType().hasName("uint32_t")
and vs_658.getParentScope+() = func
and vexchange_length_661.getParentScope+() = func
and vrecord_length_664.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
