/**
 * @name libarchive-b31744df71084a8734f97199e42418f55d08c6c5-get_time_t_max
 * @id cpp/libarchive/b31744df71084a8734f97199e42418f55d08c6c5/get-time-t-max
 * @description libarchive-b31744df71084a8734f97199e42418f55d08c6c5-libarchive/archive_read_support_format_mtree.c-get_time_t_max CVE-2015-8931
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="0"
		and target_0.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(BlockStmt target_17, Function func) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_17
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ComplementExpr target_2 |
		target_2.getValue()="-1"
		and target_2.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(VariableAccess).getType().hasName("uintmax_t")
		and target_5.getEnclosingFunction() = func)
}

predicate func_11(Variable vt_142, BlockStmt target_17, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vt_142
		and target_11.getAnOperand() instanceof Literal
		and target_11.getParent().(IfStmt).getThen()=target_17
}

predicate func_12(Variable va_143, EqualityOperation target_11, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_143
		and target_12.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_13(Variable vt_142, Variable va_143, EqualityOperation target_11, WhileStmt target_13) {
		target_13.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va_143
		and target_13.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vt_142
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_142
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_143
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_143
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=va_143
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof Literal
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_14(Variable vt_142, Variable va_143, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_142
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_143
}

/*predicate func_15(Variable va_143, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_143
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=va_143
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof Literal
}

*/
predicate func_16(Variable vt_142, ExprStmt target_14, VariableAccess target_16) {
		target_16.getTarget()=vt_142
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getLocation())
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0) instanceof ExprStmt
		and target_17.getStmt(1) instanceof WhileStmt
}

from Function func, Variable vt_142, Variable va_143, Literal target_0, EqualityOperation target_11, ExprStmt target_12, WhileStmt target_13, ExprStmt target_14, VariableAccess target_16, BlockStmt target_17
where
func_0(func, target_0)
and not func_1(target_17, func)
and not func_2(func)
and not func_5(func)
and func_11(vt_142, target_17, target_11)
and func_12(va_143, target_11, target_12)
and func_13(vt_142, va_143, target_11, target_13)
and func_14(vt_142, va_143, target_14)
and func_16(vt_142, target_14, target_16)
and func_17(target_17)
and vt_142.getType().hasName("time_t")
and va_143.getType().hasName("time_t")
and vt_142.getParentScope+() = func
and va_143.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
