/**
 * @name vim-4f1b083be43f351bc107541e7b0c9655a5d2c0bb-qf_fill_buffer
 * @id cpp/vim/4f1b083be43f351bc107541e7b0c9655a5d2c0bb/qf-fill-buffer
 * @description vim-4f1b083be43f351bc107541e7b0c9655a5d2c0bb-src/quickfix.c-qf_fill_buffer CVE-2022-3037
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vqfl_4742, BlockStmt target_2, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="qf_start"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqfl_4742
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vqfl_4742, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vqfl_4742
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vqfl_4742, BlockStmt target_2) {
		target_2.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="qf_start"
		and target_2.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqfl_4742
		and target_2.getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="qf_next"
		and target_2.getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="qf_next"
		and target_2.getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ml_line_count"
		and target_2.getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
}

from Function func, Parameter vqfl_4742, EqualityOperation target_1, BlockStmt target_2
where
not func_0(vqfl_4742, target_2, target_1)
and func_1(vqfl_4742, target_2, target_1)
and func_2(vqfl_4742, target_2)
and vqfl_4742.getType().hasName("qf_list_T *")
and vqfl_4742.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
