/**
 * @name postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-construct_md_array
 * @id cpp/postgresql/06bfbe85409177bff7bc5376fb5fdd7a324227c3/construct-md-array
 * @description postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-src/backend/utils/adt/arrayfuncs.c-construct_md_array CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vndims_3328, Parameter vdims_3329, Parameter vlbs_3330, ExprStmt target_1, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_3328
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_3329
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlbs_3330
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vndims_3328, Parameter vdims_3329, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_3328
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_3329
}

predicate func_3(Parameter vndims_3328, Parameter vdims_3329, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_3329
		and target_3.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_3328
		and target_3.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_4(Parameter vndims_3328, Parameter vlbs_3330, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="4"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ndim"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlbs_3330
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_3328
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

from Function func, Parameter vndims_3328, Parameter vdims_3329, Parameter vlbs_3330, ExprStmt target_1, ExprStmt target_3, ExprStmt target_4
where
not func_0(vndims_3328, vdims_3329, vlbs_3330, target_1, target_3, target_4, func)
and func_1(vndims_3328, vdims_3329, target_1)
and func_3(vndims_3328, vdims_3329, target_3)
and func_4(vndims_3328, vlbs_3330, target_4)
and vndims_3328.getType().hasName("int")
and vdims_3329.getType().hasName("int *")
and vlbs_3330.getType().hasName("int *")
and vndims_3328.getFunction() = func
and vdims_3329.getFunction() = func
and vlbs_3330.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
