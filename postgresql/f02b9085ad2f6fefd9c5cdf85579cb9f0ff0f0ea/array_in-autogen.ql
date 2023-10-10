/**
 * @name postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-array_in
 * @id cpp/postgresql/f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea/array-in
 * @description postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-src/backend/utils/adt/arrayfuncs.c-array_in CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vndim_194, Variable vdim_195, Variable vlBound_196, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndim_194
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdim_195
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlBound_196
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vndim_194, Variable vdim_195, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndim_194
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdim_195
}

predicate func_2(Variable vndim_194, Variable vdim_195, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ReadArrayStr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vndim_194
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdim_195
		and target_2.getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="proc"
		and target_2.getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayMetaState *")
		and target_2.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_2.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("int32")
		and target_2.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("char")
		and target_2.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getExpr().(FunctionCall).getArgument(11).(VariableAccess).getTarget().getType().hasName("char")
		and target_2.getExpr().(FunctionCall).getArgument(12).(VariableAccess).getTarget().getType().hasName("Datum *")
		and target_2.getExpr().(FunctionCall).getArgument(13).(VariableAccess).getTarget().getType().hasName("bool *")
		and target_2.getExpr().(FunctionCall).getArgument(14).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getExpr().(FunctionCall).getArgument(15).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int32")
}

predicate func_3(Variable vlBound_196, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlBound_196
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_4(Variable vndim_194, Variable vlBound_196, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="4"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ndim"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlBound_196
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndim_194
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vndim_194, Variable vdim_195, Variable vlBound_196, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vndim_194, vdim_195, vlBound_196, target_1, target_2, target_3, target_4, func)
and func_1(vndim_194, vdim_195, target_1)
and func_2(vndim_194, vdim_195, target_2)
and func_3(vlBound_196, target_3)
and func_4(vndim_194, vlBound_196, target_4)
and vndim_194.getType().hasName("int")
and vdim_195.getType().hasName("int[6]")
and vlBound_196.getType().hasName("int[6]")
and vndim_194.(LocalVariable).getFunction() = func
and vdim_195.(LocalVariable).getFunction() = func
and vlBound_196.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
