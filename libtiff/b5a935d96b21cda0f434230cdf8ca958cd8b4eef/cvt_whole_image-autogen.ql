/**
 * @name libtiff-b5a935d96b21cda0f434230cdf8ca958cd8b4eef-cvt_whole_image
 * @id cpp/libtiff/b5a935d96b21cda0f434230cdf8ca958cd8b4eef/cvt-whole-image
 * @description libtiff-b5a935d96b21cda0f434230cdf8ca958cd8b4eef-tools/tiff2rgba.c-cvt_whole_image CVE-2020-35521
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpixel_count_395, Parameter vin_389, LogicalOrExpr target_1, ExprStmt target_2, FunctionCall target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vpixel_count_395
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_389
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Raster size %lu over memory limit (%lu), try -b option."
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vpixel_count_395
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("tmsize_t")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vpixel_count_395, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vpixel_count_395
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_2(Variable vpixel_count_395, Parameter vin_389, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32 *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFCheckMalloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_389
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_count_395
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="4"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="raster buffer"
}

predicate func_3(Parameter vin_389, FunctionCall target_3) {
		target_3.getTarget().hasName("TIFFFileName")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vin_389
}

from Function func, Variable vpixel_count_395, Parameter vin_389, LogicalOrExpr target_1, ExprStmt target_2, FunctionCall target_3
where
not func_0(vpixel_count_395, vin_389, target_1, target_2, target_3, func)
and func_1(vpixel_count_395, target_1)
and func_2(vpixel_count_395, vin_389, target_2)
and func_3(vin_389, target_3)
and vpixel_count_395.getType().hasName("size_t")
and vin_389.getType().hasName("TIFF *")
and vpixel_count_395.(LocalVariable).getFunction() = func
and vin_389.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
