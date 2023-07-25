/**
 * @name php-28a6ed9f9a36b9c517e4a8a429baf4dd382fc5d5-zim_spl_SplDoublyLinkedList_offsetSet
 * @id cpp/php/28a6ed9f9a36b9c517e4a8a429baf4dd382fc5d5/zim-spl-SplDoublyLinkedList-offsetSet
 * @description php-28a6ed9f9a36b9c517e4a8a429baf4dd382fc5d5-ext/spl/spl_dllist.c-zim_spl_SplDoublyLinkedList_offsetSet CVE-2016-3132
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvalue_813, FunctionCall target_0) {
		target_0.getTarget().hasName("_zval_ptr_dtor")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vvalue_813
}

predicate func_1(LogicalOrExpr target_2, Function func, ExprStmt target_1) {
		target_1.getExpr() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("zend_long")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("zend_long")
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="llist"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("spl_dllist_object *")
}

from Function func, Variable vvalue_813, FunctionCall target_0, ExprStmt target_1, LogicalOrExpr target_2
where
func_0(vvalue_813, target_0)
and func_1(target_2, func, target_1)
and func_2(target_2)
and vvalue_813.getType().hasName("zval *")
and vvalue_813.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
