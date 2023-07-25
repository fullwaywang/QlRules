/**
 * @name openjpeg-8ee335227bbcaf1614124046aa25e53d67b11ec3-bmp_read_rle8_data
 * @id cpp/openjpeg/8ee335227bbcaf1614124046aa25e53d67b11ec3/bmp-read-rle8-data
 * @description openjpeg-8ee335227bbcaf1614124046aa25e53d67b11ec3-src/bin/jp2/convertbmp.c-bmp_read_rle8_data CVE-2018-6616
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vx_537, Variable vy_537, LogicalAndExpr target_7, RelationalOperation target_8, VariableAccess target_0) {
		target_0.getTarget()=vx_537
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_537
		and target_0.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getLocation().isBefore(target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getLesserOperand().(VariableAccess).getLocation())
}

/*predicate func_1(Variable vy_537, VariableAccess target_1) {
		target_1.getTarget()=vy_537
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
predicate func_3(Variable vx_537) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vx_537
		and target_3.getRValue().(AssignExpr).getLValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_3.getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_3.getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vwidth_535, Parameter vheight_535, LogicalAndExpr target_9, RelationalOperation target_8, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_535
		and target_6.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vheight_535
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("FILE *")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="warning, image's actual size does not match advertized one\n"
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_6)
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vwidth_535, Variable vx_537, LogicalAndExpr target_7) {
		target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vx_537
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_535
}

predicate func_8(Parameter vheight_535, Variable vy_537, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vy_537
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vheight_535
}

predicate func_9(Parameter vwidth_535, Variable vx_537, LogicalAndExpr target_9) {
		target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vx_537
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_535
}

from Function func, Parameter vwidth_535, Parameter vheight_535, Variable vx_537, Variable vy_537, VariableAccess target_0, LogicalAndExpr target_7, RelationalOperation target_8, LogicalAndExpr target_9
where
func_0(vx_537, vy_537, target_7, target_8, target_0)
and not func_3(vx_537)
and not func_4(func)
and not func_5(func)
and not func_6(vwidth_535, vheight_535, target_9, target_8, func)
and func_7(vwidth_535, vx_537, target_7)
and func_8(vheight_535, vy_537, target_8)
and func_9(vwidth_535, vx_537, target_9)
and vwidth_535.getType().hasName("OPJ_UINT32")
and vheight_535.getType().hasName("OPJ_UINT32")
and vx_537.getType().hasName("OPJ_UINT32")
and vy_537.getType().hasName("OPJ_UINT32")
and vwidth_535.getParentScope+() = func
and vheight_535.getParentScope+() = func
and vx_537.getParentScope+() = func
and vy_537.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
