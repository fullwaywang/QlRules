/**
 * @name libarchive-b31744df71084a8734f97199e42418f55d08c6c5-get_time_t_min
 * @id cpp/libarchive/b31744df71084a8734f97199e42418f55d08c6c5/get-time-t-min
 * @description libarchive-b31744df71084a8734f97199e42418f55d08c6c5-libarchive/archive_read_support_format_mtree.c-get_time_t_min CVE-2015-8931
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="0"
		and target_0.getParent().(MulExpr).getParent().(AssignExpr).getRValue() instanceof MulExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(BlockStmt target_19, Function func) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_19
		and target_1.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(VariableAccess).getType().hasName("intmax_t")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable va_165, UnaryMinusExpr target_6) {
		target_6.getValue()="-1"
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_165
}

predicate func_12(Variable vcomputed_163, BlockStmt target_19, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vcomputed_163
		and target_12.getAnOperand() instanceof Literal
		and target_12.getParent().(IfStmt).getThen()=target_19
}

predicate func_13(Variable va_165, EqualityOperation target_12, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_165
		and target_13.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_14(Variable vt_164, Variable va_165, EqualityOperation target_12, WhileStmt target_14) {
		target_14.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=va_165
		and target_14.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vt_164
		and target_14.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_164
		and target_14.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_165
		and target_14.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_165
		and target_14.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=va_165
		and target_14.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand() instanceof Literal
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_15(Variable vt_164, Variable va_165, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_164
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_165
}

/*predicate func_16(Variable va_165, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va_165
		and target_16.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=va_165
		and target_16.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand() instanceof Literal
}

*/
predicate func_17(Variable vcomputed_163, EqualityOperation target_12, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcomputed_163
		and target_17.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_18(Variable vt_164, ExprStmt target_15, VariableAccess target_18) {
		target_18.getTarget()=vt_164
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_18.getLocation())
}

predicate func_19(BlockStmt target_19) {
		target_19.getStmt(0) instanceof ExprStmt
		and target_19.getStmt(1) instanceof WhileStmt
		and target_19.getStmt(2) instanceof ExprStmt
}

from Function func, Variable vcomputed_163, Variable vt_164, Variable va_165, Literal target_0, UnaryMinusExpr target_6, EqualityOperation target_12, ExprStmt target_13, WhileStmt target_14, ExprStmt target_15, ExprStmt target_17, VariableAccess target_18, BlockStmt target_19
where
func_0(func, target_0)
and not func_1(target_19, func)
and not func_5(func)
and func_6(va_165, target_6)
and func_12(vcomputed_163, target_19, target_12)
and func_13(va_165, target_12, target_13)
and func_14(vt_164, va_165, target_12, target_14)
and func_15(vt_164, va_165, target_15)
and func_17(vcomputed_163, target_12, target_17)
and func_18(vt_164, target_15, target_18)
and func_19(target_19)
and vcomputed_163.getType().hasName("int")
and vt_164.getType().hasName("time_t")
and va_165.getType().hasName("time_t")
and vcomputed_163.getParentScope+() = func
and vt_164.getParentScope+() = func
and va_165.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
