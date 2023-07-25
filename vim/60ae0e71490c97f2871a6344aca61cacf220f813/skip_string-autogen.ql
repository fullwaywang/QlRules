/**
 * @name vim-60ae0e71490c97f2871a6344aca61cacf220f813-skip_string
 * @id cpp/vim/60ae0e71490c97f2871a6344aca61cacf220f813/skip-string
 * @description vim-60ae0e71490c97f2871a6344aca61cacf220f813-src/cindent.c-skip_string CVE-2022-1733
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_74, Variable vi_76, BlockStmt target_2, ArrayExpr target_3, EqualityOperation target_1, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_74
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_76
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_74, Variable vi_76, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_74
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_76
		and target_1.getAnOperand().(CharLiteral).getValue()="39"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vp_74, Variable vi_76, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_74
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vi_76
		and target_2.getStmt(1).(ContinueStmt).toString() = "continue;"
}

predicate func_3(Parameter vp_74, Variable vi_76, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vp_74
		and target_3.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_76
		and target_3.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vi_76, ExprStmt target_4) {
		target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_76
}

from Function func, Parameter vp_74, Variable vi_76, EqualityOperation target_1, BlockStmt target_2, ArrayExpr target_3, ExprStmt target_4
where
not func_0(vp_74, vi_76, target_2, target_3, target_1, target_4)
and func_1(vp_74, vi_76, target_2, target_1)
and func_2(vp_74, vi_76, target_2)
and func_3(vp_74, vi_76, target_3)
and func_4(vi_76, target_4)
and vp_74.getType().hasName("char_u *")
and vi_76.getType().hasName("int")
and vp_74.getParentScope+() = func
and vi_76.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
