/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-eqjoinsel_semi
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/eqjoinsel-semi
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/selfuncs.c-eqjoinsel_semi CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voperator_2476, LogicalAndExpr target_7, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voperator_2476
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen() instanceof FunctionCall
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvardata1_2477, BlockStmt target_8, ExprStmt target_4, ExprStmt target_9) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("statistic_proc_security_check")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vvardata1_2477
		and target_1.getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vvardata2_2477, Variable vhave_mcvs2_2491, Variable vvalues2_2492, Variable vnvalues2_2493, Variable vnumbers2_2494, Variable vnnumbers2_2495, ExprStmt target_10, ExprStmt target_11, LogicalAndExpr target_7, ArrayExpr target_14, ExprStmt target_16, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("statistic_proc_security_check")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvardata2_2477
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhave_mcvs2_2491
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvalues2_2492
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnvalues2_2493
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnumbers2_2494
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnnumbers2_2495
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_2)
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_14.getArrayBase().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vvardata1_2477, Variable vhave_mcvs1_2486, Variable vvalues1_2487, Variable vnvalues1_2488, Variable vnumbers1_2489, Variable vnnumbers1_2490, EqualityOperation target_19, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhave_mcvs1_2486
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata1_2477
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata1_2477
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata1_2477
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvalues1_2487
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnvalues1_2488
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnumbers1_2489
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnnumbers1_2490
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_5(Parameter vvardata2_2477, BlockStmt target_8, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen()=target_8
}

predicate func_6(Parameter voperator_2476, FunctionCall target_6) {
		target_6.getTarget().hasName("get_opcode")
		and target_6.getArgument(0).(VariableAccess).getTarget()=voperator_2476
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fmgr_info")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("FmgrInfo")
}

predicate func_7(Variable vhave_mcvs1_2486, Variable vhave_mcvs2_2491, Parameter voperator_2476, LogicalAndExpr target_7) {
		target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vhave_mcvs1_2486
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vhave_mcvs2_2491
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voperator_2476
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Parameter vvardata2_2477, Variable vhave_mcvs2_2491, Variable vvalues2_2492, Variable vnvalues2_2493, Variable vnumbers2_2494, Variable vnnumbers2_2495, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhave_mcvs2_2491
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_attstatsslot")
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvalues2_2492
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnvalues2_2493
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnumbers2_2494
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnnumbers2_2495
}

predicate func_9(Parameter vvardata1_2477, Variable vvalues1_2487, Variable vnvalues1_2488, Variable vnumbers1_2489, Variable vnnumbers1_2490, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata1_2477
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalues1_2487
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnvalues1_2488
		and target_9.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnumbers1_2489
		and target_9.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnnumbers1_2490
}

predicate func_10(Parameter vvardata2_2477, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("double")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rel"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget().getType().hasName("double")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="rows"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rel"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
}

predicate func_11(Parameter vvardata2_2477, Variable vvalues2_2492, Variable vnvalues2_2493, Variable vnumbers2_2494, Variable vnnumbers2_2495, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata2_2477
		and target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalues2_2492
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnvalues2_2493
		and target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnumbers2_2494
		and target_11.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnnumbers2_2495
}

predicate func_14(Variable vvalues2_2492, ArrayExpr target_14) {
		target_14.getArrayBase().(VariableAccess).getTarget()=vvalues2_2492
		and target_14.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_16(Variable vnvalues2_2493, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnvalues2_2493
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("double")
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnvalues2_2493
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget().getType().hasName("double")
}

predicate func_19(Parameter vvardata1_2477, EqualityOperation target_19) {
		target_19.getAnOperand().(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata1_2477
		and target_19.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vvardata1_2477, Parameter vvardata2_2477, Variable vhave_mcvs1_2486, Variable vvalues1_2487, Variable vnvalues1_2488, Variable vnumbers1_2489, Variable vnnumbers1_2490, Variable vhave_mcvs2_2491, Variable vvalues2_2492, Variable vnvalues2_2493, Variable vnumbers2_2494, Variable vnnumbers2_2495, Parameter voperator_2476, ExprStmt target_4, EqualityOperation target_5, FunctionCall target_6, LogicalAndExpr target_7, BlockStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ArrayExpr target_14, ExprStmt target_16, EqualityOperation target_19
where
not func_0(voperator_2476, target_7, func)
and not func_1(vvardata1_2477, target_8, target_4, target_9)
and not func_2(vvardata2_2477, vhave_mcvs2_2491, vvalues2_2492, vnvalues2_2493, vnumbers2_2494, vnnumbers2_2495, target_10, target_11, target_7, target_14, target_16, func)
and func_4(vvardata1_2477, vhave_mcvs1_2486, vvalues1_2487, vnvalues1_2488, vnumbers1_2489, vnnumbers1_2490, target_19, target_4)
and func_5(vvardata2_2477, target_8, target_5)
and func_6(voperator_2476, target_6)
and func_7(vhave_mcvs1_2486, vhave_mcvs2_2491, voperator_2476, target_7)
and func_8(vvardata2_2477, vhave_mcvs2_2491, vvalues2_2492, vnvalues2_2493, vnumbers2_2494, vnnumbers2_2495, target_8)
and func_9(vvardata1_2477, vvalues1_2487, vnvalues1_2488, vnumbers1_2489, vnnumbers1_2490, target_9)
and func_10(vvardata2_2477, target_10)
and func_11(vvardata2_2477, vvalues2_2492, vnvalues2_2493, vnumbers2_2494, vnnumbers2_2495, target_11)
and func_14(vvalues2_2492, target_14)
and func_16(vnvalues2_2493, target_16)
and func_19(vvardata1_2477, target_19)
and vvardata1_2477.getType().hasName("VariableStatData *")
and vvardata2_2477.getType().hasName("VariableStatData *")
and vhave_mcvs1_2486.getType().hasName("bool")
and vvalues1_2487.getType().hasName("Datum *")
and vnvalues1_2488.getType().hasName("int")
and vnumbers1_2489.getType().hasName("float4 *")
and vnnumbers1_2490.getType().hasName("int")
and vhave_mcvs2_2491.getType().hasName("bool")
and vvalues2_2492.getType().hasName("Datum *")
and vnvalues2_2493.getType().hasName("int")
and vnumbers2_2494.getType().hasName("float4 *")
and vnnumbers2_2495.getType().hasName("int")
and voperator_2476.getType().hasName("Oid")
and vvardata1_2477.getFunction() = func
and vvardata2_2477.getFunction() = func
and vhave_mcvs1_2486.(LocalVariable).getFunction() = func
and vvalues1_2487.(LocalVariable).getFunction() = func
and vnvalues1_2488.(LocalVariable).getFunction() = func
and vnumbers1_2489.(LocalVariable).getFunction() = func
and vnnumbers1_2490.(LocalVariable).getFunction() = func
and vhave_mcvs2_2491.(LocalVariable).getFunction() = func
and vvalues2_2492.(LocalVariable).getFunction() = func
and vnvalues2_2493.(LocalVariable).getFunction() = func
and vnumbers2_2494.(LocalVariable).getFunction() = func
and vnnumbers2_2495.(LocalVariable).getFunction() = func
and voperator_2476.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
