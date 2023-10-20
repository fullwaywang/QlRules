/**
 * @name vim-cc762a48d42b579fb7bdec2c614636b830342dd5-check_text_locked
 * @id cpp/vim/cc762a48d42b579fb7bdec2c614636b830342dd5/check-text-locked
 * @description vim-cc762a48d42b579fb7bdec2c614636b830342dd5-src/normal.c-check_text_locked CVE-2022-4141
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voap_187, FunctionCall target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voap_187
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter voap_187, FunctionCall target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("clearopbeep")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_187
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(FunctionCall target_2) {
		target_2.getTarget().hasName("text_locked")
}

from Function func, Parameter voap_187, ExprStmt target_1, FunctionCall target_2
where
not func_0(voap_187, target_2, target_1)
and func_1(voap_187, target_2, target_1)
and func_2(target_2)
and voap_187.getType().hasName("oparg_T *")
and voap_187.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
