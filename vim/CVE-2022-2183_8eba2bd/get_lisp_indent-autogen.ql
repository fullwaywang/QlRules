/**
 * @name vim-8eba2bd291b347e3008aa9e565652d51ad638cfa-get_lisp_indent
 * @id cpp/vim/8eba2bd291b347e3008aa9e565652d51ad638cfa/get-lisp-indent
 * @description vim-8eba2bd291b347e3008aa9e565652d51ad638cfa-src/indent.c-get_lisp_indent CVE-2022-2183
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vthat_1970, LogicalAndExpr target_3, PointerArithmeticOperation target_4, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vthat_1970, LogicalAndExpr target_3, ExprStmt target_1) {
		target_1.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Variable vamount_1969, LogicalAndExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vamount_1969
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vthat_1970, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="40"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="91"
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("lisp_match")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vthat_1970
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vthat_1970, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vthat_1970
		and target_4.getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vamount_1969, Variable vthat_1970, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3, PointerArithmeticOperation target_4
where
not func_0(vthat_1970, target_3, target_4, target_1)
and func_1(vthat_1970, target_3, target_1)
and func_2(vamount_1969, target_3, target_2)
and func_3(vthat_1970, target_3)
and func_4(vthat_1970, target_4)
and vamount_1969.getType().hasName("int")
and vthat_1970.getType().hasName("char_u *")
and vamount_1969.getParentScope+() = func
and vthat_1970.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
