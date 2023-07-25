/**
 * @name libgit2-e1832eb20a7089f6383cfce474f213157f5300cb-only_spaces_and_dots
 * @id cpp/libgit2/e1832eb20a7089f6383cfce474f213157f5300cb/only-spaces-and-dots
 * @description libgit2-e1832eb20a7089f6383cfce474f213157f5300cb-src/path.c-only_spaces_and_dots CVE-2020-12278
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_1646, ReturnStmt target_2, PostfixIncrExpr target_3, EqualityOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_1646
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_1646, ReturnStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_1646
		and target_1.getAnOperand().(CharLiteral).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="1"
}

predicate func_3(Variable vc_1646, PostfixIncrExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vc_1646
}

from Function func, Variable vc_1646, EqualityOperation target_1, ReturnStmt target_2, PostfixIncrExpr target_3
where
not func_0(vc_1646, target_2, target_3, target_1)
and func_1(vc_1646, target_2, target_1)
and func_2(target_2)
and func_3(vc_1646, target_3)
and vc_1646.getType().hasName("const char *")
and vc_1646.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
