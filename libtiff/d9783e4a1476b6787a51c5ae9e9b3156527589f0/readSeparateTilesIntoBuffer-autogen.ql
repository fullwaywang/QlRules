/**
 * @name libtiff-d9783e4a1476b6787a51c5ae9e9b3156527589f0-readSeparateTilesIntoBuffer
 * @id cpp/libtiff/d9783e4a1476b6787a51c5ae9e9b3156527589f0/readSeparateTilesIntoBuffer
 * @description libtiff-d9783e4a1476b6787a51c5ae9e9b3156527589f0-tools/tiffcrop.c-readSeparateTilesIntoBuffer CVE-2016-5321
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_963, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vs_963
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vspp_954, Variable vs_963, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vs_963
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vspp_954
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Variable vs_963, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadTile")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("unsigned char *[8]")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vs_963
}

predicate func_3(Variable vs_963, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_963
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vspp_954, Variable vs_963, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vs_963, target_2, target_3, target_1)
and func_1(vspp_954, vs_963, target_2, target_1)
and func_2(vs_963, target_2)
and func_3(vs_963, target_3)
and vspp_954.getType().hasName("uint16")
and vs_963.getType().hasName("tsample_t")
and vspp_954.getFunction() = func
and vs_963.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
