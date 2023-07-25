/**
 * @name e2fsprogs-ab51d587bb9b229b1fade1afd02e1574c1ba5c76-ext2fs_extent_delete
 * @id cpp/e2fsprogs/ab51d587bb9b229b1fade1afd02e1574c1ba5c76/ext2fs-extent-delete
 * @description e2fsprogs-ab51d587bb9b229b1fade1afd02e1574c1ba5c76-lib/ext2fs/extent.c-ext2fs_extent_delete CVE-2022-1304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpath_1601, ExprStmt target_1, IfStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="left"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpath_1601
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="2133571449"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpath_1601, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="curr"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpath_1601
}

predicate func_2(Variable vpath_1601, IfStmt target_2) {
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="left"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpath_1601
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="12"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="left"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpath_1601
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="12"
		and target_2.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="curr"
		and target_2.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpath_1601
}

from Function func, Variable vpath_1601, ExprStmt target_1, IfStmt target_2
where
not func_0(vpath_1601, target_1, target_2, func)
and func_1(vpath_1601, target_1)
and func_2(vpath_1601, target_2)
and vpath_1601.getType().hasName("extent_path *")
and vpath_1601.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
