/**
 * @name vim-9b4a80a66544f2782040b641498754bcb5b8d461-set_curbuf
 * @id cpp/vim/9b4a80a66544f2782040b641498754bcb5b8d461/set-curbuf
 * @description vim-9b4a80a66544f2782040b641498754bcb5b8d461-src/buffer.c-set_curbuf CVE-2022-0443
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0))
}

predicate func_2(LogicalOrExpr target_5, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("enter_buffer")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("buf_T *")
		and target_2.getElse() instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vbuf_1699, FunctionCall target_3) {
		target_3.getTarget().hasName("buf_valid")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vbuf_1699
}

predicate func_4(Parameter vbuf_1699, LogicalOrExpr target_5, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("enter_buffer")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1699
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Parameter vbuf_1699, LogicalOrExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_1699
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("aborting")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vbuf_1699, FunctionCall target_3, ExprStmt target_4, LogicalOrExpr target_5
where
not func_0(func)
and not func_2(target_5, func)
and func_3(vbuf_1699, target_3)
and func_4(vbuf_1699, target_5, target_4)
and func_5(vbuf_1699, target_5)
and vbuf_1699.getType().hasName("buf_T *")
and vbuf_1699.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
