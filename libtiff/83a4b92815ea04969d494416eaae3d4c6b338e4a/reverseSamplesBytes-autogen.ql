/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-reverseSamplesBytes
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/reverseSamplesBytes
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-tools/tiffcrop.c-reverseSamplesBytes CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbytes_per_pixel_8904, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytes_per_pixel_8904
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="32"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="reverseSamplesBytes"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="bytes_per_pixel too large"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbytes_per_pixel_8904, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_pixel_8904
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_2(Variable vbytes_per_pixel_8904, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_pixel_8904
}

from Function func, Variable vbytes_per_pixel_8904, ExprStmt target_1, ExprStmt target_2
where
not func_0(vbytes_per_pixel_8904, target_1, target_2, func)
and func_1(vbytes_per_pixel_8904, target_1)
and func_2(vbytes_per_pixel_8904, target_2)
and vbytes_per_pixel_8904.getType().hasName("uint32")
and vbytes_per_pixel_8904.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()