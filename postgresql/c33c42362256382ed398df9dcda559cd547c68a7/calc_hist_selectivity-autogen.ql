/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-calc_hist_selectivity
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/calc-hist-selectivity
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/rangetypes_selfuncs.c-calc_hist_selectivity CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtypcache_371, Parameter vvardata_371, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_371
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="fn_oid"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rng_cmp_proc_finfo"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypcache_371
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1.0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vtypcache_371, Parameter vvardata_371, ExprStmt target_9, NotExpr target_10, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="fn_oid"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rng_subdiff_finfo"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypcache_371
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata_371
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="fn_oid"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rng_subdiff_finfo"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypcache_371
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1.0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1)
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vvardata_371, Variable vhist_values_374, Variable vnhist_375, NotExpr target_11, ArrayExpr target_12, RelationalOperation target_13) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhist_values_374
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnhist_375
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_13.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vvardata_371, Variable vlength_hist_values_376, Variable vlength_nhist_377, RelationalOperation target_14, AddressOfExpr target_15, ExprStmt target_16) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_hist_values_376
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_nhist_377
		and target_3.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_15.getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vvardata_371, Variable vhist_values_374, Variable vnhist_375, RelationalOperation target_14, ExprStmt target_17) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhist_values_374
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnhist_375
		and target_4.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vvardata_371, Variable vlength_hist_values_376, Variable vlength_nhist_377, ExprStmt target_18, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_hist_values_376
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_nhist_377
		and target_5.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_5)
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vvardata_371, Variable vhist_values_374, Variable vnhist_375, ExprStmt target_18, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhist_values_374
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnhist_375
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_6)
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_7(NotExpr target_11, Function func, ReturnStmt target_7) {
		target_7.getExpr().(UnaryMinusExpr).getValue()="-1.0"
		and target_7.getParent().(IfStmt).getCondition()=target_11
		and target_7.getEnclosingFunction() = func
}

predicate func_8(RelationalOperation target_14, Function func, ReturnStmt target_8) {
		target_8.getExpr().(UnaryMinusExpr).getValue()="-1.0"
		and target_8.getParent().(IfStmt).getCondition()=target_14
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vtypcache_371, Variable vhist_values_374, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("range_deserialize")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypcache_371
		and target_9.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("pg_detoast_datum")
		and target_9.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhist_values_374
		and target_9.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("RangeBound *")
		and target_9.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("RangeBound *")
		and target_9.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_10(Parameter vvardata_371, Variable vhist_values_374, Variable vnhist_375, NotExpr target_10) {
		target_10.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="7"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhist_values_374
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnhist_375
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_10.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
}

predicate func_11(Parameter vvardata_371, Variable vlength_hist_values_376, Variable vlength_nhist_377, NotExpr target_11) {
		target_11.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_371
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="6"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_hist_values_376
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_nhist_377
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_11.getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
}

predicate func_12(Variable vhist_values_374, ArrayExpr target_12) {
		target_12.getArrayBase().(VariableAccess).getTarget()=vhist_values_374
		and target_12.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_13(Variable vnhist_375, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vnhist_375
}

predicate func_14(Variable vlength_nhist_377, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(VariableAccess).getTarget()=vlength_nhist_377
		and target_14.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_15(Variable vlength_hist_values_376, AddressOfExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vlength_hist_values_376
}

predicate func_16(Parameter vtypcache_371, Variable vnhist_375, Variable vlength_hist_values_376, Variable vlength_nhist_377, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calc_hist_selectivity_contains")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypcache_371
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RangeBound")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RangeBound")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("RangeBound *")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnhist_375
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vlength_hist_values_376
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vlength_nhist_377
}

predicate func_17(Parameter vtypcache_371, Variable vnhist_375, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calc_hist_selectivity_scalar")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypcache_371
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RangeBound")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("RangeBound *")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnhist_375
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_18(Parameter vtypcache_371, Variable vnhist_375, Variable vlength_hist_values_376, Variable vlength_nhist_377, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calc_hist_selectivity_contained")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypcache_371
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RangeBound")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RangeBound")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("RangeBound *")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnhist_375
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vlength_hist_values_376
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vlength_nhist_377
}

from Function func, Parameter vtypcache_371, Parameter vvardata_371, Variable vhist_values_374, Variable vnhist_375, Variable vlength_hist_values_376, Variable vlength_nhist_377, ReturnStmt target_7, ReturnStmt target_8, ExprStmt target_9, NotExpr target_10, NotExpr target_11, ArrayExpr target_12, RelationalOperation target_13, RelationalOperation target_14, AddressOfExpr target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18
where
not func_0(vtypcache_371, vvardata_371, func)
and not func_1(vtypcache_371, vvardata_371, target_9, target_10, func)
and not func_2(vvardata_371, vhist_values_374, vnhist_375, target_11, target_12, target_13)
and not func_3(vvardata_371, vlength_hist_values_376, vlength_nhist_377, target_14, target_15, target_16)
and not func_4(vvardata_371, vhist_values_374, vnhist_375, target_14, target_17)
and not func_5(vvardata_371, vlength_hist_values_376, vlength_nhist_377, target_18, func)
and not func_6(vvardata_371, vhist_values_374, vnhist_375, target_18, func)
and func_7(target_11, func, target_7)
and func_8(target_14, func, target_8)
and func_9(vtypcache_371, vhist_values_374, target_9)
and func_10(vvardata_371, vhist_values_374, vnhist_375, target_10)
and func_11(vvardata_371, vlength_hist_values_376, vlength_nhist_377, target_11)
and func_12(vhist_values_374, target_12)
and func_13(vnhist_375, target_13)
and func_14(vlength_nhist_377, target_14)
and func_15(vlength_hist_values_376, target_15)
and func_16(vtypcache_371, vnhist_375, vlength_hist_values_376, vlength_nhist_377, target_16)
and func_17(vtypcache_371, vnhist_375, target_17)
and func_18(vtypcache_371, vnhist_375, vlength_hist_values_376, vlength_nhist_377, target_18)
and vtypcache_371.getType().hasName("TypeCacheEntry *")
and vvardata_371.getType().hasName("VariableStatData *")
and vhist_values_374.getType().hasName("Datum *")
and vnhist_375.getType().hasName("int")
and vlength_hist_values_376.getType().hasName("Datum *")
and vlength_nhist_377.getType().hasName("int")
and vtypcache_371.getFunction() = func
and vvardata_371.getFunction() = func
and vhist_values_374.(LocalVariable).getFunction() = func
and vnhist_375.(LocalVariable).getFunction() = func
and vlength_hist_values_376.(LocalVariable).getFunction() = func
and vlength_nhist_377.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
