/**
 * @name libtiff-48d6ece8389b01129e7d357f0985c8f938ce3da3-process_command_opts
 * @id cpp/libtiff/48d6ece8389b01129e7d357f0985c8f938ce3da3/process-command-opts
 * @description libtiff-48d6ece8389b01129e7d357f0985c8f938ce3da3-tools/tiffcrop.c-process_command_opts CVE-2022-2953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="The crop options(-X|-Y), -Z and -z are mutually exclusive.->Exit"
		and not target_0.getValue()="The crop options(-X|-Y), -Z, -z and -S are mutually exclusive.->Exit"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vXY_2135, VariableAccess target_1) {
		target_1.getTarget()=vXY_2135
}

predicate func_3(Variable vXY_2135) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition() instanceof LogicalOrExpr
		and target_3.getThen().(Literal).getValue()="1"
		and target_3.getElse().(Literal).getValue()="0"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vXY_2135)
}

predicate func_4(Variable vZ_2135) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition() instanceof BitwiseAndExpr
		and target_4.getThen().(Literal).getValue()="1"
		and target_4.getElse().(Literal).getValue()="0"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vZ_2135)
}

predicate func_5(Variable vR_2135) {
	exists(ConditionalExpr target_5 |
		target_5.getCondition() instanceof BitwiseAndExpr
		and target_5.getThen().(Literal).getValue()="1"
		and target_5.getElse().(Literal).getValue()="0"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vR_2135)
}

predicate func_6(Parameter vpage_1629, ExprStmt target_15, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_1629
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_6)
		and target_15.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Variable vXY_2135, Variable vZ_2135, Variable vR_2135, BlockStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vXY_2135
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vZ_2135
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vR_2135
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("char")
		and target_7.getLesserOperand().(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getThen()=target_16
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vcrop_data_1629, Variable vXY_2135, LogicalOrExpr target_8) {
		target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_data_1629
		and target_8.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_data_1629
		and target_8.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vXY_2135
}

predicate func_9(Parameter vcrop_data_1629, Variable vZ_2135, BitwiseAndExpr target_9) {
		target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_data_1629
		and target_9.getRightOperand().(Literal).getValue()="8"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vZ_2135
}

predicate func_10(Parameter vcrop_data_1629, Variable vR_2135, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_data_1629
		and target_10.getRightOperand().(Literal).getValue()="16"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vR_2135
}

predicate func_11(Variable vXY_2135, VariableAccess target_11) {
		target_11.getTarget()=vXY_2135
}

predicate func_12(Variable vZ_2135, VariableAccess target_12) {
		target_12.getTarget()=vZ_2135
}

predicate func_13(Variable vR_2135, VariableAccess target_13) {
		target_13.getTarget()=vR_2135
}

predicate func_14(Variable vXY_2135, Variable vZ_2135, Variable vR_2135, BlockStmt target_16, LogicalOrExpr target_14) {
		target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vXY_2135
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vZ_2135
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vXY_2135
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vR_2135
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vZ_2135
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vR_2135
		and target_14.getParent().(IfStmt).getThen()=target_16
}

predicate func_15(Parameter vpage_1629, ExprStmt target_15) {
		target_15.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mode"
		and target_15.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_1629
		and target_15.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1"
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="tiffcrop input error"
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_16.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_16.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
}

predicate func_17(Variable vXY_2135, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vXY_2135
		and target_17.getExpr().(AssignExpr).getRValue() instanceof LogicalOrExpr
}

predicate func_18(Variable vZ_2135, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vZ_2135
		and target_18.getExpr().(AssignExpr).getRValue() instanceof BitwiseAndExpr
}

predicate func_19(Variable vR_2135, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vR_2135
		and target_19.getExpr().(AssignExpr).getRValue() instanceof BitwiseAndExpr
}

from Function func, Parameter vcrop_data_1629, Parameter vpage_1629, Variable vXY_2135, Variable vZ_2135, Variable vR_2135, StringLiteral target_0, VariableAccess target_1, LogicalOrExpr target_8, BitwiseAndExpr target_9, BitwiseAndExpr target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, LogicalOrExpr target_14, ExprStmt target_15, BlockStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19
where
func_0(func, target_0)
and func_1(vXY_2135, target_1)
and not func_3(vXY_2135)
and not func_4(vZ_2135)
and not func_5(vR_2135)
and not func_6(vpage_1629, target_15, func)
and not func_7(vXY_2135, vZ_2135, vR_2135, target_16, target_17, target_18, target_19)
and func_8(vcrop_data_1629, vXY_2135, target_8)
and func_9(vcrop_data_1629, vZ_2135, target_9)
and func_10(vcrop_data_1629, vR_2135, target_10)
and func_11(vXY_2135, target_11)
and func_12(vZ_2135, target_12)
and func_13(vR_2135, target_13)
and func_14(vXY_2135, vZ_2135, vR_2135, target_16, target_14)
and func_15(vpage_1629, target_15)
and func_16(target_16)
and func_17(vXY_2135, target_17)
and func_18(vZ_2135, target_18)
and func_19(vR_2135, target_19)
and vcrop_data_1629.getType().hasName("crop_mask *")
and vpage_1629.getType().hasName("pagedef *")
and vXY_2135.getType().hasName("char")
and vZ_2135.getType().hasName("char")
and vR_2135.getType().hasName("char")
and vcrop_data_1629.getFunction() = func
and vpage_1629.getFunction() = func
and vXY_2135.(LocalVariable).getFunction() = func
and vZ_2135.(LocalVariable).getFunction() = func
and vR_2135.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
