/**
 * @name vim-15d9890eee53afc61eb0a03b878a19cb5672f732-suggest_trie_walk
 * @id cpp/vim/15d9890eee53afc61eb0a03b878a19cb5672f732/suggest-trie-walk
 * @description vim-15d9890eee53afc61eb0a03b878a19cb5672f732-src/spellsuggest.c-suggest_trie_walk CVE-2021-3928
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpreword_1250, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpreword_1250
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_1268, Variable vcurwin, BlockStmt target_2, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("spell_iswordp")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_1268
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcurwin
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vpreword_1250, Variable vp_1268, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_1268
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpreword_1250
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpreword_1250
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(VariableAccess).getTarget()=vp_1268
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vpreword_1250
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_3(Variable vpreword_1250, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("add_sound_suggest")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpreword_1250
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="ts_score"
}

predicate func_4(Variable vpreword_1250, Variable vp_1268, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_1268
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpreword_1250
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpreword_1250
}

from Function func, Variable vpreword_1250, Variable vp_1268, Variable vcurwin, NotExpr target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vpreword_1250, target_2, target_3, target_4)
and func_1(vp_1268, vcurwin, target_2, target_1)
and func_2(vpreword_1250, vp_1268, target_2)
and func_3(vpreword_1250, target_3)
and func_4(vpreword_1250, vp_1268, target_4)
and vpreword_1250.getType().hasName("char_u[762]")
and vp_1268.getType().hasName("char_u *")
and vcurwin.getType().hasName("win_T *")
and vpreword_1250.getParentScope+() = func
and vp_1268.getParentScope+() = func
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
