/**
 * @name vim-5e59ea54c0c37c2f84770f068d95280069828774-store_word
 * @id cpp/vim/5e59ea54c0c37c2f84770f068d95280069828774/store-word
 * @description vim-5e59ea54c0c37c2f84770f068d95280069828774-src/spellfile.c-store_word CVE-2022-2287
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vword_4381, FunctionCall target_0) {
		target_0.getTarget().hasName("utf_valid_string")
		and not target_0.getTarget().hasName("valid_spell_word")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vword_4381
		and target_0.getArgument(1).(Literal).getValue()="0"
}

predicate func_1(Variable venc_utf8, ReturnStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=venc_utf8
		and target_1.getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vword_4381, Variable venc_utf8, FunctionCall target_0, LogicalAndExpr target_1, ReturnStmt target_2
where
func_0(vword_4381, target_0)
and func_1(venc_utf8, target_2, target_1)
and func_2(target_2)
and vword_4381.getType().hasName("char_u *")
and venc_utf8.getType().hasName("int")
and vword_4381.getParentScope+() = func
and not venc_utf8.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
