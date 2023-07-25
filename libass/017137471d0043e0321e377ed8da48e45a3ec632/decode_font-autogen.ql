/**
 * @name libass-017137471d0043e0321e377ed8da48e45a3ec632-decode_font
 * @id cpp/libass/017137471d0043e0321e377ed8da48e45a3ec632/decode-font
 * @description libass-017137471d0043e0321e377ed8da48e45a3ec632-libass/ass.c-decode_font CVE-2020-36430
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="dsize == size / 4 * 3 + FFMAX(size % 4 - 1, 0)"
		and not target_0.getValue()="dsize == size / 4 * 3 + FFMAX(size % 4, 1) - 1"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent().(GTExpr).getParent().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand() instanceof RemExpr
		and target_1.getParent().(GTExpr).getParent().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vsize_849, RemExpr target_2) {
		target_2.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_2.getRightOperand().(Literal).getValue()="4"
}

predicate func_3(Variable vsize_849, RemExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_3.getRightOperand().(Literal).getValue()="4"
}

predicate func_4(Variable vsize_849, RemExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_4.getRightOperand() instanceof Literal
}

predicate func_5(Variable vsize_849, RemExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_5.getRightOperand() instanceof Literal
}

predicate func_6(Variable vsize_849, RemExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_6.getRightOperand() instanceof Literal
}

predicate func_7(Variable vsize_849, RemExpr target_7) {
		target_7.getLeftOperand().(VariableAccess).getTarget()=vsize_849
		and target_7.getRightOperand() instanceof Literal
}

predicate func_11(Function func, SubExpr target_11) {
		target_11.getLeftOperand() instanceof RemExpr
		and target_11.getRightOperand() instanceof Literal
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, SubExpr target_12) {
		target_12.getLeftOperand() instanceof RemExpr
		and target_12.getRightOperand() instanceof Literal
		and target_12.getParent().(GTExpr).getLesserOperand() instanceof Literal
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, SubExpr target_13) {
		target_13.getLeftOperand() instanceof RemExpr
		and target_13.getRightOperand() instanceof Literal
		and target_13.getEnclosingFunction() = func
}

from Function func, Variable vsize_849, StringLiteral target_0, Literal target_1, RemExpr target_2, RemExpr target_3, RemExpr target_4, RemExpr target_5, RemExpr target_6, RemExpr target_7, SubExpr target_11, SubExpr target_12, SubExpr target_13
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vsize_849, target_2)
and func_3(vsize_849, target_3)
and func_4(vsize_849, target_4)
and func_5(vsize_849, target_5)
and func_6(vsize_849, target_6)
and func_7(vsize_849, target_7)
and func_11(func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and vsize_849.getType().hasName("size_t")
and vsize_849.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
