/**
 * @name postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-array_set_slice
 * @id cpp/postgresql/06bfbe85409177bff7bc5376fb5fdd7a324227c3/array-set-slice
 * @description postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-src/backend/utils/adt/arrayfuncs.c-array_set_slice CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vndim_2776, Variable vdim_2777, Variable vlb_2778, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndim_2776
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdim_2777
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlb_2778
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vndim_2776, Variable vdim_2777, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndim_2776
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdim_2777
}

predicate func_2(Variable vndim_2776, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("mda_get_range")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndim_2776
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int[6]")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int *")
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int *")
}

predicate func_3(Variable vndim_2776, Variable vdim_2777, Variable vlb_2778, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("array_slice_size")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dataoffset"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="dataoffset"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dataoffset"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ndim"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vndim_2776
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdim_2777
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vlb_2778
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("int *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("bool")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getTarget().getType().hasName("char")
}

predicate func_4(Variable vdim_2777, Variable vlb_2778, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int *")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdim_2777
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlb_2778
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vndim_2776, Variable vdim_2777, Variable vlb_2778, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vndim_2776, vdim_2777, vlb_2778, target_1, target_2, target_3, target_4, func)
and func_1(vndim_2776, vdim_2777, target_1)
and func_2(vndim_2776, target_2)
and func_3(vndim_2776, vdim_2777, vlb_2778, target_3)
and func_4(vdim_2777, vlb_2778, target_4)
and vndim_2776.getType().hasName("int")
and vdim_2777.getType().hasName("int[6]")
and vlb_2778.getType().hasName("int[6]")
and vndim_2776.(LocalVariable).getFunction() = func
and vdim_2777.(LocalVariable).getFunction() = func
and vlb_2778.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
