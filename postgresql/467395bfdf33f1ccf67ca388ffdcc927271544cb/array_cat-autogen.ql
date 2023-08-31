/**
 * @name postgresql-467395bfdf33f1ccf67ca388ffdcc927271544cb-array_cat
 * @id cpp/postgresql/467395bfdf33f1ccf67ca388ffdcc927271544cb/array-cat
 * @description postgresql-467395bfdf33f1ccf67ca388ffdcc927271544cb-src/backend/utils/adt/array_userfuncs.c-array_cat CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdims_223, Variable vlbs_224, Variable vndims_225, ExprStmt target_1, ExprStmt target_2, LogicalOrExpr target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_225
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_223
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlbs_224
		and (func.getEntryPoint().(BlockStmt).getStmt(39)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(39).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdims_223, Variable vndims_225, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_225
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_223
}

predicate func_2(Variable vdims_223, Variable vndims_225, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_223
		and target_2.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_225
		and target_2.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_3(Variable vdims_223, Variable vlbs_224, LogicalOrExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int *")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdims_223
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int *")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlbs_224
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vlbs_224, Variable vndims_225, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="4"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ndim"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlbs_224
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_225
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vdims_223, Variable vlbs_224, Variable vndims_225, ExprStmt target_1, ExprStmt target_2, LogicalOrExpr target_3, ExprStmt target_4
where
not func_0(vdims_223, vlbs_224, vndims_225, target_1, target_2, target_3, target_4, func)
and func_1(vdims_223, vndims_225, target_1)
and func_2(vdims_223, vndims_225, target_2)
and func_3(vdims_223, vlbs_224, target_3)
and func_4(vlbs_224, vndims_225, target_4)
and vdims_223.getType().hasName("int *")
and vlbs_224.getType().hasName("int *")
and vndims_225.getType().hasName("int")
and vdims_223.(LocalVariable).getFunction() = func
and vlbs_224.(LocalVariable).getFunction() = func
and vndims_225.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
