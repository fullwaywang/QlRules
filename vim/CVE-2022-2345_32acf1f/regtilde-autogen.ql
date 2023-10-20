/**
 * @name vim-32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea-regtilde
 * @id cpp/vim/32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea/regtilde
 * @description vim-32acf1f1a72ebb9d8942b9c9d80023bf1bb668ea-src/regexp.c-regtilde CVE-2022-2345
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnewsub_1721, Variable vreg_prev_sub, EqualityOperation target_2, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreg_prev_sub
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_strsave")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewsub_1721
		and target_0.getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Parameter vsource_1719, Variable vnewsub_1721, Variable vreg_prev_sub, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewsub_1721
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsource_1719
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreg_prev_sub
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnewsub_1721
		and target_1.getElse() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vsource_1719, Variable vnewsub_1721, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vnewsub_1721
		and target_2.getAnOperand().(VariableAccess).getTarget()=vsource_1719
}

from Function func, Parameter vsource_1719, Variable vnewsub_1721, Variable vreg_prev_sub, ExprStmt target_0, IfStmt target_1, EqualityOperation target_2
where
func_0(vnewsub_1721, vreg_prev_sub, target_2, target_0)
and func_1(vsource_1719, vnewsub_1721, vreg_prev_sub, func, target_1)
and func_2(vsource_1719, vnewsub_1721, target_2)
and vsource_1719.getType().hasName("char_u *")
and vnewsub_1721.getType().hasName("char_u *")
and vreg_prev_sub.getType().hasName("char_u *")
and vsource_1719.getParentScope+() = func
and vnewsub_1721.getParentScope+() = func
and not vreg_prev_sub.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
