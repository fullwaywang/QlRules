/**
 * @name vim-71223e2db87c2bf3b09aecb46266b56cda26191d-buflist_getfile
 * @id cpp/vim/71223e2db87c2bf3b09aecb46266b56cda26191d/buflist-getfile
 * @description vim-71223e2db87c2bf3b09aecb46266b56cda26191d-src/buffer.c-buflist_getfile CVE-2022-1942
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("curbuf_locked")
		and not target_0.getTarget().hasName("text_or_buf_locked")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(FunctionCall target_5, Function func, ReturnStmt target_1) {
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, IfStmt target_2) {
		target_2.getCondition().(FunctionCall).getTarget().hasName("text_locked")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("text_locked_msg")
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(FunctionCall target_5, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("text_locked_msg")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_4(Function func, ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(FunctionCall target_5) {
		target_5.getTarget().hasName("text_locked")
}

from Function func, FunctionCall target_0, ReturnStmt target_1, IfStmt target_2, ReturnStmt target_4, FunctionCall target_5
where
func_0(func, target_0)
and func_1(target_5, func, target_1)
and func_2(func, target_2)
and func_4(func, target_4)
and func_5(target_5)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
