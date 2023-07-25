/**
 * @name vim-5e59ea54c0c37c2f84770f068d95280069828774-spell_add_word
 * @id cpp/vim/5e59ea54c0c37c2f84770f068d95280069828774/spell-add-word
 * @description vim-5e59ea54c0c37c2f84770f068d95280069828774-src/spellfile.c-spell_add_word CVE-2022-2287
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vword_6180, FunctionCall target_0) {
		target_0.getTarget().hasName("utf_valid_string")
		and not target_0.getTarget().hasName("valid_spell_word")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vword_6180
		and target_0.getArgument(1).(Literal).getValue()="0"
}

predicate func_1(Variable venc_utf8, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=venc_utf8
		and target_1.getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("emsg")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_2.getStmt(1).(ReturnStmt).toString() = "return ..."
}

from Function func, Variable venc_utf8, Parameter vword_6180, FunctionCall target_0, LogicalAndExpr target_1, BlockStmt target_2
where
func_0(vword_6180, target_0)
and func_1(venc_utf8, target_2, target_1)
and func_2(target_2)
and venc_utf8.getType().hasName("int")
and vword_6180.getType().hasName("char_u *")
and not venc_utf8.getParentScope+() = func
and vword_6180.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
