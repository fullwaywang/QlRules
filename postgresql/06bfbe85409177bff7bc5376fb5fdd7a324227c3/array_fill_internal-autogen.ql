/**
 * @name postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-array_fill_internal
 * @id cpp/postgresql/06bfbe85409177bff7bc5376fb5fdd7a324227c3/array-fill-internal
 * @description postgresql-06bfbe85409177bff7bc5376fb5fdd7a324227c3-src/backend/utils/adt/arrayfuncs.c-array_fill_internal CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdimv_5786, Variable vlbsv_5787, Variable vndims_5788, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_5788
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdimv_5786
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlbsv_5787
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdimv_5786, Variable vndims_5788, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_5788
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdimv_5786
}

predicate func_2(Variable vdimv_5786, Variable vlbsv_5787, Variable vndims_5788, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("create_array_envelope")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_5788
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdimv_5786
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlbsv_5787
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_3(Variable vlbsv_5787, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlbsv_5787
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int[6]")
}

predicate func_4(Variable vndims_5788, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vndims_5788
		and target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getValue()="7"
		and target_4.getExpr().(AssignAddExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="18446744073709551608"
}

from Function func, Variable vdimv_5786, Variable vlbsv_5787, Variable vndims_5788, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vdimv_5786, vlbsv_5787, vndims_5788, target_1, target_2, target_3, target_4, func)
and func_1(vdimv_5786, vndims_5788, target_1)
and func_2(vdimv_5786, vlbsv_5787, vndims_5788, target_2)
and func_3(vlbsv_5787, target_3)
and func_4(vndims_5788, target_4)
and vdimv_5786.getType().hasName("int *")
and vlbsv_5787.getType().hasName("int *")
and vndims_5788.getType().hasName("int")
and vdimv_5786.(LocalVariable).getFunction() = func
and vlbsv_5787.(LocalVariable).getFunction() = func
and vndims_5788.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
