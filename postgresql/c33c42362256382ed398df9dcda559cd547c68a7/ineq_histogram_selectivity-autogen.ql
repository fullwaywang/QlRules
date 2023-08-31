/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-ineq_histogram_selectivity
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/ineq-histogram-selectivity
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/selfuncs.c-ineq_histogram_selectivity CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvardata_752, Parameter vopproc_753, BlockStmt target_2, LogicalAndExpr target_3, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_752
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fn_oid"
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopproc_753
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Oid")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvardata_752, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Oid")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_actual_variable_range")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(WhileStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(WhileStmt).getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_3(Parameter vvardata_752, LogicalAndExpr target_3) {
		target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_752
		and target_3.getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_3.getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getAnOperand().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Oid")
		and target_3.getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_3.getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_3.getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
}

predicate func_4(Parameter vopproc_753, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("bool")
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("FunctionCall2Coll")
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vopproc_753
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(1).(Literal).getValue()="100"
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("Datum")
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vvardata_752, Parameter vopproc_753, EqualityOperation target_1, BlockStmt target_2, LogicalAndExpr target_3, ExprStmt target_4
where
not func_0(vvardata_752, vopproc_753, target_2, target_3, target_4)
and func_1(vvardata_752, target_2, target_1)
and func_2(target_2)
and func_3(vvardata_752, target_3)
and func_4(vopproc_753, target_4)
and vvardata_752.getType().hasName("VariableStatData *")
and vopproc_753.getType().hasName("FmgrInfo *")
and vvardata_752.getFunction() = func
and vopproc_753.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
