/**
 * @name postgresql-935e77d527a018b652f247c7374c558871210db6-calc_hist_selectivity
 * @id cpp/postgresql/935e77d527a018b652f247c7374c558871210db6/calc-hist-selectivity
 * @description postgresql-935e77d527a018b652f247c7374c558871210db6-src/backend/utils/adt/rangetypes_selfuncs.c-calc_hist_selectivity CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vvardata_372) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-1"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="6"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0")
}

predicate func_4(Parameter vvardata_372, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="atttype"
		and target_4.getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_5(Parameter vvardata_372, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="atttype"
		and target_5.getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_6(Parameter vvardata_372, NotExpr target_8, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="atttype"
		and target_6.getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getQualifier().(VariableAccess).getLocation())
}

predicate func_7(Parameter vvardata_372, ExprStmt target_9, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="atttypmod"
		and target_7.getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_7.getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_8(Parameter vvardata_372, NotExpr target_8) {
		target_8.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="6"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_8.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
}

predicate func_9(Parameter vvardata_372, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_372
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

from Function func, Parameter vvardata_372, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, NotExpr target_8, ExprStmt target_9
where
not func_1(vvardata_372)
and func_4(vvardata_372, target_4)
and func_5(vvardata_372, target_5)
and func_6(vvardata_372, target_8, target_6)
and func_7(vvardata_372, target_9, target_7)
and func_8(vvardata_372, target_8)
and func_9(vvardata_372, target_9)
and vvardata_372.getType().hasName("VariableStatData *")
and vvardata_372.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
