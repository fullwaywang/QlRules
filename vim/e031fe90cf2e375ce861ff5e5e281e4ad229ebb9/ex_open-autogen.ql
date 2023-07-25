/**
 * @name vim-e031fe90cf2e375ce861ff5e5e281e4ad229ebb9-ex_open
 * @id cpp/vim/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9/ex-open
 * @description vim-e031fe90cf2e375ce861ff5e5e281e4ad229ebb9-src/ex_docmd.c-ex_open CVE-2021-4069
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_6863, ExprStmt target_5, VariableAccess target_0) {
		target_0.getTarget()=vp_6863
		and target_0.getParent().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_5
}

predicate func_1(Variable vp_6863, VariableAccess target_1) {
		target_1.getTarget()=vp_6863
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("vim_free")
		and target_2.getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func, FunctionCall target_3) {
		target_3.getTarget().hasName("ml_get_curline")
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vp_6863, AssignExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vp_6863
		and target_4.getRValue() instanceof FunctionCall
}

predicate func_5(Variable vp_6863, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="startp"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_6863
}

from Function func, Variable vp_6863, VariableAccess target_0, VariableAccess target_1, FunctionCall target_3, AssignExpr target_4, ExprStmt target_5
where
func_0(vp_6863, target_5, target_0)
and func_1(vp_6863, target_1)
and not func_2(func)
and func_3(func, target_3)
and func_4(vp_6863, target_4)
and func_5(vp_6863, target_5)
and vp_6863.getType().hasName("char_u *")
and vp_6863.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
