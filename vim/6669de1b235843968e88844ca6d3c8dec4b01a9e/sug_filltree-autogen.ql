/**
 * @name vim-6669de1b235843968e88844ca6d3c8dec4b01a9e-sug_filltree
 * @id cpp/vim/6669de1b235843968e88844ca6d3c8dec4b01a9e/sug-filltree
 * @description vim-6669de1b235843968e88844ca6d3c8dec4b01a9e-src/spellfile.c-sug_filltree CVE-2022-2923
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbyts_5566, Variable vidxs_5567, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbyts_5566
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vidxs_5567
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbyts_5566, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbyts_5566
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="sl_fbyts"
}

predicate func_2(Variable vbyts_5566, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbyts_5566
}

predicate func_3(Variable vidxs_5567, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vidxs_5567
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="sl_fidxs"
}

predicate func_4(Variable vidxs_5567, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vidxs_5567
}

from Function func, Variable vbyts_5566, Variable vidxs_5567, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vbyts_5566, vidxs_5567, target_1, target_2, target_3, target_4, func)
and func_1(vbyts_5566, target_1)
and func_2(vbyts_5566, target_2)
and func_3(vidxs_5567, target_3)
and func_4(vidxs_5567, target_4)
and vbyts_5566.getType().hasName("char_u *")
and vidxs_5567.getType().hasName("idx_T *")
and vbyts_5566.getParentScope+() = func
and vidxs_5567.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
