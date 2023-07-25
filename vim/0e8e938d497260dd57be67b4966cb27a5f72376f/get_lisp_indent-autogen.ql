/**
 * @name vim-0e8e938d497260dd57be67b4966cb27a5f72376f-get_lisp_indent
 * @id cpp/vim/0e8e938d497260dd57be67b4966cb27a5f72376f/get-lisp-indent
 * @description vim-0e8e938d497260dd57be67b4966cb27a5f72376f-src/indent.c-get_lisp_indent CVE-2022-2125
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vthat_1970, LogicalAndExpr target_4, ExprStmt target_5, LogicalOrExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Function func, LabelStmt target_2) {
		target_2.toString() = "label ...:"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, LabelStmt target_3) {
		target_3.toString() = "label ...:"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vthat_1970, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="34"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vthat_1970
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vthat_1970, ExprStmt target_5) {
		target_5.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
}

predicate func_6(Variable vthat_1970, LogicalOrExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="40"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vthat_1970
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="91"
}

from Function func, Variable vthat_1970, LabelStmt target_2, LabelStmt target_3, LogicalAndExpr target_4, ExprStmt target_5, LogicalOrExpr target_6
where
not func_0(vthat_1970, target_4, target_5, target_6)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(vthat_1970, target_4)
and func_5(vthat_1970, target_5)
and func_6(vthat_1970, target_6)
and vthat_1970.getType().hasName("char_u *")
and vthat_1970.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
